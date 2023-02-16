import { agent } from './setup'

async function main() {
  const identifier = await agent.createIdentifierV1({
    options: { version: '1' },
  })
  //   console.log(identifier["keys"][0]);
  //   const verifiableAuthorization = await agent.getVerifiableAuthorization();
  //   const res = await agent.createVerifiablePresentation({
  //     presentation: {
  //       holder: identifier.did,
  //       verifier: [],
  //       "@context": ["https://nekaj.com,", "https://nekaj2.com"],
  //       type: ["VerifiablePresentation", "Custom"],
  //       issuanceDate: new Date().toISOString(),
  //       verifiableCredential: [verifiableAuthorization],
  //     },
  //     proofFormat: "jwt",
  //   });
}

main().catch(console.log)
