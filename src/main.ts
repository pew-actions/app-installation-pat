import * as core from '@actions/core'
import { Octokit } from '@octokit/core'
import { App } from '@octokit/app'

function parseScopes(scopes: string): object {
  var result = {}

  const items = scopes.toLowerCase().split(',')
  for (const item of items) {
    const parts = item.split(':')
    console.log(`S: ${item}`)
    if (parts.length != 2) {
      throw new Error(`Invalid scope '${item.trim()}'`)
    }

    const name = parts[0].trim()
    const value = parts[1].trim()

    // validate name
    switch (name) {
    case 'actions':
    case 'administration':
    case 'checks':
    case 'contents':
    case 'deployments':
    case 'enviornments':
    case 'issues':
    case 'metadata':
    case 'packages':
    case 'pages':
    case 'pull_requests':
    case 'repository_announcement_banners':
    case 'repository_hooks':
    case 'repository_projects':
    case 'secret_scanning_alerts':
    case 'security_events':
    case 'single_file':
    case 'statuses':
    case 'vulnerability_alerts':
    case 'workflows':
    case 'members':
    case 'organization_administration':
    case 'organization_custom_roles':
    case 'organization_announcement_banners':
    case 'organization_hooks':
    case 'organization_plan':
    case 'organization_projects':
    case 'organization_packages':
    case 'organization_secrets':
    case 'organization_self_hosted_runners':
    case 'organization_user_blocking':
    case 'team_discussions':
      break

    default:
      throw new Error(`Invalid scope name '${name}' from '${item.trim()}'`)
    }

    // Validate value
    switch (value) {
      case 'read':
      case 'write':
        break

      default:
        throw new Error(`Invalid scope value '${value}' from '${item.trim()}'`)
    }

    result[name] = value;
  }

  return result
}

async function run(): Promise<void> {

  core.saveState('isPost', true)

  try {
    // Verify inputs
    const applicationId = core.getInput('application-id')
    if (!applicationId) {
      core.setFailed('No application-id supplied to the action')
      return
    }

    const installationId = parseInt(core.getInput('installation-id'))
    if (!installationId) {
      core.setFailed('No installation-id supplied to the action')
      return
    }

    const privateKey = core.getInput('private-key')
    if (!privateKey) {
      core.setFailed('No private-key supplied to the action')
      return
    }

    const scopes = core.getInput('scope')
    if (!scopes) {
      core.setFailed('No scopes supplied to the action')
      return
    }

    const permissions = parseScopes(scopes)
    if (!permissions) {
      core.setFailed('Failed to parse scopes')
      return
    }

    const repositoryList = core.getInput('repositories') || process.env.GITHUB_REPOSITORY

    const repositories =
      repositoryList == "all"
        ? undefined
        : repositoryList!.split(',').map((function(name: string) {
            const parts = name.split('/')
            if (parts.length != 2) {
              throw new Error(`Invalid repository name: '${name}'`)
            }

            return parts[1].trim()
          }))

    // Authenticate as our application
    const app = new App({
      appId: applicationId,
      privateKey: privateKey,
    })

    {
      const { data } = await app.octokit.request("/app")
      console.log(`Authenticated as application ${data.name}`)
    }


    // Create an access token for the repository
    const octokit = await app.getInstallationOctokit(installationId)
    const { data } = await octokit.request('POST /app/installations/{installation_id}/access_tokens', {
      installation_id: installationId,
      repositories: repositories,
      permissions: permissions,
    })

    core.setSecret(data.token)
    core.saveState('token', data.token)
    core.setOutput('token', data.token)

    const actualRepositories = (data.repositories || [{full_name: 'all'}]).map(
        function(repository) { return repository.full_name }
    )

    // Output repositories/permissions granted to the token
    console.log(`Token has access to ${actualRepositories}`)
    console.log(`  with permissions: ${JSON.stringify(data.permissions || {})}`)

  } catch (err: any) {
    if (err instanceof Error) {
      const error = err as Error
      core.setFailed(error.message)
    } else {
      throw(err)
    }
  }
}

async function post(): Promise<void> {
  const token = core.getState('token')
  if (token) {
    try {
      const octokit = new Octokit({
        auth: token
      })

      await octokit.request('DELETE /installation/token', {})
      console.log('Revoked installation access token')
    } catch (err: any) {
      if (err instanceof Error) {
        const error = err as Error
        core.warning(error.message)
      }
    }
  }
}

if (!core.getState('isPost')) {
  run()
} else {
  post()
}
