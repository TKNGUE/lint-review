from __future__ import absolute_import
import os
import logging
import shutil
import subprocess
import six
from functools import wraps
from six.moves.urllib.parse import urlparse, urlunparse

log = logging.getLogger(__name__)


def log_io_error(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except IOError as e:
            log.error(str(e))
            raise
    return wrapper


def get_repo_path(user, repo, number, settings):
    """Get the target path a repo should be cloned into for the parameters.
    """
    try:
        path = settings['WORKSPACE']
    except:
        raise KeyError("You have not defined the WORKSPACE config"
                       " option. This is required for lintreview to work.")
    path = path.rstrip('/')
    path = os.path.join(path, user, repo, str(number))
    return os.path.realpath(path)



@log_io_error
def clone(url, path):
    """Clone a repository from `url` into `path`
    """
    command = ['git', 'clone', url, path]
    return_code, _ = _process(command)
    if return_code:
        raise IOError(u"Unable to clone repository '{}'".format(url))
    return True


@log_io_error
def fetch(path, remote):
    """Run git fetch on a repository
    """
    command = ['git','fetch', remote]
    return_code, _ = _process(command, chdir=path)
    if return_code:
        raise IOError(u"Unable to fetch new changes '{}'".format(path))
    return True


def generate_url(config, url):
    from six.moves.urllib.parse import urlparse, urlunparse

    # Add auth to url
    parsed_url = urlparse(url)
    if 'GITHUB_OAUTH_TOKEN' in config:
        user = config['GITHUB_OAUTH_TOKEN']
        password = 'x-oauth-basic'
    elif 'GITHUB_APP_INSTALLATION_ID' in config:
        user = 'x-access-token'
        password = make_auth_token(config['GITHUB_APP_INSTALLATION_ID'])
    else:
        user = config['GITHUB_USER']
        password = config['GITHUB_PASSWORD']

    url = urlunparse((
        parsed_url[0], (u'{}:{}@{}'.format(user, password, parsed_url[1]))
    ) + parsed_url[2:])

    return url


def clone_or_update(config, url, path, pr_branch, private=False):
    """Clone a new repository and checkout commit,
    or update an existing clone to the new pr_branch
    """
    log.info("Cloning/Updating repository '%s' into '%s'", url, path)
    master_path = os.path.join(os.path.dirname(path), "base")

    if exists(master_path):
        fetch(master_path, url if not private else generate_url(config, url))
    else:
        clone(url if not private else generate_url(config, url), master_path)
        create_branch(master_path, "refuse")

    if exists(path):
        log.debug("Path '%s' does exist, updating existing clone.", path)
        reset(path, 'origin/{}'.format(pr_branch))
    else:
        log.debug('Repository does not exist, cloning a new one.')
        add_worktree(master_path, path, pr_branch)

    log.info("Checking out '%s'", pr_branch)


@log_io_error
def add_worktree(path, dest_path, branch_name):
    """Check out `ref` in the repo located on `path`
    """

    command = ['git', 'worktree', "add", os.path.abspath(dest_path), branch_name]
    return_code, _ = _process(command, chdir=path)
    if return_code:
        raise IOError(
            u"Unable to add worktree '{}' to '{}'".format(branch_name, path))
    return True


@log_io_error
def reset(path, ref):
    """check out `ref` in the repo located on `path`
    """
    command = ['git', 'reset', '--hard', ref]
    return_code, _ = _process(command, chdir=path)
    if return_code:
        raise ioerror(u"unable to reset '{}'".format(ref))
    return True


@log_io_error
def checkout(path, ref):
    """check out `ref` in the repo located on `path`
    """
    command = ['git', 'checkout', ref]
    return_code, _ = _process(command, chdir=path)
    if return_code:
        raise ioerror(u"unable to checkout '{}'".format(ref))
    return true


@log_io_error
def diff(path):
    """Get a diff of the unstaged changes.
    See lintreview.diff.parse_diff if you need to create
    more useful objects from the diff.
    """
    command = ['git', 'diff', '--patience']
    return_code, output = _process(command, chdir=path)
    if return_code:
        raise IOError(u"Unable to create diff '{}'".format(output))
    return output


@log_io_error
def apply_cached(path, patch):
    """Apply a patch to the index.

    This function allows patches to be applied to the stage/index
    without modifying the working tree.
    """
    command = ['git', 'apply', '--cached']
    if not len(patch):
        return ''
    return_code, output = _process(command, input_val=patch, chdir=path)
    if return_code:
        raise IOError(u"Unable to stage changes '{}'".format(output))
    return output


@log_io_error
def status(path):
    """Get the working status of path"""
    command = ['git', 'status', '-s']
    return_code, output = _process(command, chdir=path)
    if return_code:
        raise IOError(u"Unable to get status '{}'".format(output))
    return output


@log_io_error
def commit(path, author, message):
    """Commit the staged changes in the repository"""
    command = ['git', 'commit', '--author', author, '-m', message]
    return_code, output = _process(command, chdir=path)
    if return_code:
        raise IOError(u"Unable to commit changes '{}'".format(output))
    return output


@log_io_error
def create_branch(path, name):
    """Create & checkout a local branch based
    on the currently checked out commit
    """
    command = ['git', '-C', path, 'checkout', '-b', name]
    return_code, output = _process(command)
    if return_code:
        raise IOError(u"Unable to create branch {}:{}. {}'".format(
                      path, name, output))


@log_io_error
def branch_exists(path, name):
    """See if a branch exists"""
    command = ['git', 'branch']
    return_code, output = _process(command, chdir=path)
    if return_code:
        raise IOError(u"Unable to read branches {}'".format(output))
    matching = [branch for branch in output.split('\n')
                if branch.strip('* ') == name]
    return len(matching) == 1


@log_io_error
def push(path, remote, branch):
    """Push a branch to the named remote"""
    command = ['git', 'push', remote, branch]
    return_code, output = _process(command, chdir=path)
    if return_code:
        raise IOError(u"Unable to push changes to {}:{}. {}'".format(
                      remote,
                      branch,
                      output))
    return output


@log_io_error
def add_remote(path, name, url):
    """Add a remote to the repo at `path`
    Generally used to add a push remote to a repo
    for fixer flows.
    """
    command = ['git', 'remote', 'add', name, url]
    return_code, output = _process(command, chdir=path)
    if return_code:
        raise IOError(u"Unable to add remote {}. {}'".format(
                      name,
                      output))
    return output


@log_io_error
def destroy(path):
    """Blow up a repo and all its contents.
    """
    shutil.rmtree(path, False)


def exists(path):
    """Check if a path exists, and contains a git repo.

    returns false if either conditions is not true.
    """
    try:
        path = os.path.join(path, '.git')
        log.debug("Checking for path '%s'", path)
        os.stat(path)
        return True
    except:
        log.debug('Path does not exist, or .git dir was missing')
        return False


def _process(command, input_val=None, chdir=False):
    """Helper method for running processes related to git.
    """
    if chdir:
        log.debug('Changing directories to %s', chdir)
        cwd = os.getcwd()
        os.chdir(chdir)

    log.debug('Running %s', command)

    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False)
    if isinstance(input_val, six.string_types):
        input_val = input_val.encode()
    output, error = process.communicate(input=input_val)
    return_code = process.returncode

    if chdir:
        os.chdir(cwd)
    if return_code > 0:
        log.error('STDERR output: %s', error)

    return return_code, (output + error).decode('utf-8')
