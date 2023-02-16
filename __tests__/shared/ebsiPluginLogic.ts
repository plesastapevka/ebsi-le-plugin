import { TAgent, IMessageHandler } from '@veramo/core'
import { IEbsiPlugin } from '../../src/types/IEbsiPlugin'

type ConfiguredAgent = TAgent<IEbsiPlugin & IMessageHandler>

export default (testContext: {
  getAgent: () => ConfiguredAgent
  setup: () => Promise<boolean>
  tearDown: () => Promise<boolean>
}) => {
  describe('my plugin', () => {
    let agent: ConfiguredAgent

    beforeAll(() => {
      testContext.setup()
      agent = testContext.getAgent()
    })
    afterAll(testContext.tearDown)

    it('should return created identifier', async () => {
      const result = await agent.createIdentifierV1({
        options: { version: "1" }
      })
      expect(result).toEqual({ foobar: 'ipsum' })
    })
  })
}
