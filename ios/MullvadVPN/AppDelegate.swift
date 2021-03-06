//
//  AppDelegate.swift
//  MullvadVPN
//
//  Created by pronebird on 19/03/2019.
//  Copyright © 2019 Mullvad VPN AB. All rights reserved.
//

import Combine
import UIKit

@UIApplicationMain
class AppDelegate: UIResponder, UIApplicationDelegate {

    var window: UIWindow?

    let mainStoryboard = UIStoryboard(name: "Main", bundle: nil)

    #if targetEnvironment(simulator)
    let simulatorTunnelProvider = SimulatorTunnelProviderHost()
    #endif


    private var loadTunnelSubscriber: AnyCancellable?

    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        #if targetEnvironment(simulator)
        SimulatorTunnelProvider.shared.delegate = simulatorTunnelProvider
        #endif

        let accountToken = Account.shared.token

        loadTunnelSubscriber = TunnelManager.shared.loadTunnel(accountToken: accountToken)
            .receive(on: DispatchQueue.main)
            .sink(receiveCompletion: { (completion) in
                if case .failure(let error) = completion {
                    fatalError("Failed to restore the account: \(error.localizedDescription)")
                }

                let rootViewController = self.mainStoryboard.instantiateViewController(identifier: ViewControllerIdentifier.root.rawValue) as! RootContainerViewController

                if Account.shared.isAgreedToTermsOfService {
                    self.showMainController(in: rootViewController, animated: false)
                } else {
                    self.showTermsOfService(in: rootViewController) {
                        Account.shared.agreeToTermsOfService()

                        self.showMainController(in: rootViewController, animated: true)
                    }
                }

                self.window?.rootViewController = rootViewController
            })

        return true
    }

    private func showTermsOfService(in rootViewController: RootContainerViewController, completionHandler: @escaping () -> Void) {
        let consentViewController = self.mainStoryboard.instantiateViewController(withIdentifier: ViewControllerIdentifier.consent.rawValue) as! ConsentViewController

        consentViewController.completionHandler = completionHandler

        rootViewController.setViewControllers([consentViewController], animated: false)
    }

    private func showMainController(in rootViewController: RootContainerViewController, animated: Bool) {
        let loginViewController = self.mainStoryboard.instantiateViewController(withIdentifier: ViewControllerIdentifier.login.rawValue)

        var viewControllers = [loginViewController]

        if Account.shared.isLoggedIn {
            let mainViewController = self.mainStoryboard.instantiateViewController(withIdentifier: ViewControllerIdentifier.main.rawValue)

            viewControllers.append(mainViewController)
        }

        rootViewController.setViewControllers(viewControllers, animated: animated)
    }

    func applicationWillResignActive(_ application: UIApplication) {
        // Sent when the application is about to move from active to inactive state. This can occur for certain types of temporary interruptions (such as an incoming phone call or SMS message) or when the user quits the application and it begins the transition to the background state.
        // Use this method to pause ongoing tasks, disable timers, and invalidate graphics rendering callbacks. Games should use this method to pause the game.
    }

    func applicationDidEnterBackground(_ application: UIApplication) {
        // Use this method to release shared resources, save user data, invalidate timers, and store enough application state information to restore your application to its current state in case it is terminated later.
        // If your application supports background execution, this method is called instead of applicationWillTerminate: when the user quits.
    }

    func applicationWillEnterForeground(_ application: UIApplication) {
        // Called as part of the transition from the background to the active state; here you can undo many of the changes made on entering the background.
    }

    func applicationDidBecomeActive(_ application: UIApplication) {
        // Restart any tasks that were paused (or not yet started) while the application was inactive. If the application was previously in the background, optionally refresh the user interface.
    }

    func applicationWillTerminate(_ application: UIApplication) {
        // Called when the application is about to terminate. Save data if appropriate. See also applicationDidEnterBackground:.
    }

}
