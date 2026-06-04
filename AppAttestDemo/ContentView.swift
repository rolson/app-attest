import AppAttest
import SwiftUI

let attestationManager = AttestationManager()

struct ContentView: View {

    @State private var status = ""

    var body: some View {
        VStack {
            Button("Submit Attestation") {
                Task { await submitAttestation() }
            }
            .buttonStyle(.bordered)
            .padding()

            Button("Hello World") {
                Task { await helloWorld() }
            }
            .buttonStyle(.bordered)
            .padding()

            Button("Reset Attestation") {
                resetAttestation()
            }
            .buttonStyle(.bordered)
            .padding()

            Text(status)
                .padding()
        }
        .padding()
    }

    func submitAttestation() async {
        status = "submitting attestation..."
        do {
            let didAttest = try await attestationManager.submitAttestation()
            status = didAttest
                ? "successfully submitted attestation"
                : "already attested on this install (reusing stored keyID)"
        } catch {
            status = "failed to submit attestation: \(error.localizedDescription)"
        }
    }

    func helloWorld() async {
        status = "calling HW..."
        do {
            try await attestationManager.helloWorld()
            status = "HW succeeded"
        } catch {
            status = "HW failed: \(error.localizedDescription)"
        }
    }

    func resetAttestation() {
        attestationManager.resetAttestation()
        status = "cleared stored keyID - run Submit Attestation again"
    }
}

#Preview {
    ContentView()
}
