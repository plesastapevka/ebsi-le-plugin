import { getConfig } from '@veramo/cli/build/setup'
import { createObjects } from '@veramo/cli/build/lib/objectCreator'
import { DataSource } from 'typeorm'

import fs from 'fs'

jest.setTimeout(30000)

// Shared tests
import myPluginLogic from './shared/ebsiPluginLogic'
import myPluginEventsLogic from './shared/ebsiPluginEventsLogic'

let dbConnection: DataSource
let agent: any

const setup = async (): Promise<boolean> => {

  const config = getConfig('./agent.yml')

  const { localAgent, db } = createObjects(config, { localAgent: '/agent', db: '/dbConnection' })
  agent = localAgent
  dbConnection = db

  return true
}

const tearDown = async (): Promise<boolean> => {
  try {
    await dbConnection.dropDatabase()
    await dbConnection.close()
    fs.unlinkSync('./database.sqlite')
  } catch (e: any) {
    // nop
  }
  return true
}

const getAgent = () => agent

const testContext = { getAgent, setup, tearDown }

describe('Local integration tests', () => {
  myPluginLogic(testContext)
  myPluginEventsLogic(testContext)
})
