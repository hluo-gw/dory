import Foundation
import Security

/// Code-signing requirement the RawHV runner and its filesystem worker apply to each other.
///
/// A build signed by Dory's team keeps the exact team-bound requirement. An ad-hoc developer or
/// fork build has no team identity and can never satisfy that requirement, so it checks the peer's
/// signing identifier only. This is the same split `DorydXPCSecurity` applies to doryd's Mach
/// service. A build carrying any other non-empty team identity keeps the production requirement
/// and therefore fails closed.
public enum DoryFSWorkerPeerSigningPolicy {
    public static let productionTeamID = "864H636QW4"
    public static let runnerIdentifier = "com.pythonxi.Dory.HVRunner"
    public static let workerIdentifier = "com.pythonxi.Dory.HVRunner.FSWorker"

    public static func requirement(
        peerIdentifier: String,
        ownTeamIdentifier: String? = currentTeamIdentifier()
    ) -> String {
        guard let ownTeamIdentifier, !ownTeamIdentifier.isEmpty else {
            return "identifier \"\(peerIdentifier)\""
        }
        return "anchor apple generic and identifier \"\(peerIdentifier)\" "
            + "and certificate leaf[subject.OU] = \"\(productionTeamID)\""
    }

    /// Team identifier of the running process's own signature, or nil for an ad-hoc signature.
    public static func currentTeamIdentifier() -> String? {
        var code: SecCode?
        guard SecCodeCopySelf(SecCSFlags(), &code) == errSecSuccess,
              let code else {
            return nil
        }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, SecCSFlags(), &staticCode) == errSecSuccess,
              let staticCode else {
            return nil
        }
        var signingInformation: CFDictionary?
        let flags = SecCSFlags(rawValue: kSecCSSigningInformation)
        guard SecCodeCopySigningInformation(staticCode, flags, &signingInformation) == errSecSuccess,
              let values = signingInformation as? [CFString: Any],
              let team = values[kSecCodeInfoTeamIdentifier] as? String,
              !team.isEmpty else {
            return nil
        }
        return team
    }
}
