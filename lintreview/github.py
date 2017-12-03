from __future__ import absolute_import

import logging
import github3
import jwt
import requests
from functools import partial

log = logging.getLogger(__name__)


def get_private_pem():
    path = os.environ.get('GITHUB_APP_SECRETFILE', None);
    with open(path) as fp:
        return fp.read()


def make_auth_token(installation_id):
    utcnow = datetime.utcnow()
    duration = timedelta(seconds=60)
    payload = {
        "iat": utcnow,
        "exp": utcnow + duration,
        "iss": config.get('GITHUB_APP_ID')
    }
    pem = get_private_pem()
    encoded = jwt.encode(payload, pem, "RS256")
    headers = {
        "Authorization": "Bearer " + encoded.decode("utf-8"),
        "Accept": "application/vnd.github.machine-man-preview+json"
    }

    auth_url = "https://api.github.com/installations/{}/access_tokens".format(
        installation_id
    )
    r = requests.post(auth_url, headers=headers)

    if not r.ok:
        print(r.json()["message"])
        r.raise_for_status()

    token = r.json()["token"]
    return token


def get_client(config):
    """
    Factory for the Github client
    """
    login = github3.login
    if config.get('GITHUB_URL', GITHUB_BASE_URL) != GITHUB_BASE_URL:
        login = partial(github3.enterprise_login, url=config['GITHUB_URL'])

    if 'GITHUB_OAUTH_TOKEN' in config:
        return login(username=config['GITHUB_USER'],
                     token=config['GITHUB_OAUTH_TOKEN'])

    if 'GITHUB_APP_INSTALLATION_ID' in config:
        return login(
            username=config['GITHUB_USER'],
            token=make_auth_token(config['GITHUB_APP_INSTALLATION_ID'])
        )

    return login(username=config['GITHUB_USER'],
                 password=config['GITHUB_PASSWORD'])


def get_repository(config, user, repo):
    gh = get_client(config)
    return gh.repository(owner=user, repository=repo)


def get_lintrc(repo, ref):
    """
    Download the .lintrc from a repo
    """
    log.info('Fetching lintrc file')
    response = repo.file_contents('.lintrc', ref)
    return response.decoded


def register_hook(repo, hook_url):
    """
    Register a new hook with a user's repository.
    """
    log.info('Registering webhook for %s on %s', hook_url, repo.full_name)
    hooks = repo.hooks()
    found = False
    for hook in hooks:
        if hook.name != 'web':
            continue
        if hook.config['url'] == hook_url:
            found = True
            break

    if found:
        msg = ("Found existing hook. "
               "No additional hooks registered.")
        log.warn(msg)
        return

    hook = {
        'name': 'web',
        'active': True,
        'config': {
            'url': hook_url,
            'content_type': 'json',
        },
        'events': ['pull_request']
    }
    try:
        repo.create_hook(**hook)
    except:
        message = ("Unable to save webhook. You need to have administration"
                   "privileges over the repository to add webhooks.")
        log.error(message)
        raise
    log.info('Registered hook successfully')


def unregister_hook(repo, hook_url):
    """
    Remove a registered webhook.
    """
    log.info('Removing webhook for %s on %s', hook_url, repo.full_name)
    hooks = repo.hooks()
    hook_id = False
    for hook in hooks:
        if hook.name != 'web':
            continue
        if hook.config['url'] == hook_url:
            hook_id = hook.id
            break

    if not hook_id:
        msg = ("Could not find hook for '%s' "
               "No hooks removed.") % (hook_url)
        log.error(msg)
        raise Exception(msg)
    try:
        repo.hook(hook_id).delete()
    except:
        message = ("Unable to remove webhook. You will need admin "
                   "privileges over the repository to remove webhooks.")
        log.error(message)
        raise
    log.info('Removed hook successfully')
