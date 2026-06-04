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
            
            Button("Assertion") {
                Task { await assertion() }
            }
            .buttonStyle(.bordered)
            .padding()
            
            Button("Hello World") {
                Task { await helloWorld() }
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
            try await attestationManager.submitAttestation()
            status = "successfully submited attestation"
        } catch {
            status = "failed to subumit attestation: \(error.localizedDescription)"
        }
    }
    
    func assertion() async {
        status = "doing assertion..."
        do {
            let assertion = try await attestationManager.getAssertion()
            status = "assertion succeeded: \(assertion.count)"
        } catch {
            status = "failed to do assertion: \(error.localizedDescription)"
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
}

#Preview {
    ContentView()
}
