import os
import requests

API_TOKEN = os.getenv("API_TOKEN")
GITLAB_URL = os.getenv("GITLAB_URL")
VERIFY = False

class GitlabUtils(object):
    @staticmethod
    def get_builds(project_id: int):
        req = requests.get(
            '{}/api/v3/projects/{}/builds'.format(GITLAB_URL, project_id),
            headers={'PRIVATE-TOKEN': API_TOKEN},
            verify=VERIFY
        )
        if req.status_code != 200:
            return []
        return req.json()

    @staticmethod
    def get_build_artifacts(project_id: int, build_id: int):
        req = requests.get(
            '{}/api/v3/projects/{}/builds/{}/artifacts'.format(GITLAB_URL, project_id, build_id),
            headers={'PRIVATE-TOKEN': API_TOKEN},
            verify=VERIFY
        )
        if req.status_code != 200:
            return None
        return req.content

    @staticmethod
    def get_latest_build(project_id: int, job: str):
        builds = [x for x in GitlabUtils.get_builds(project_id) if x['name'] == job]
        builds.sort(key=lambda x: x['id'], reverse=True)
        return builds[0] if len(builds) > 0 else None

    @staticmethod
    def get_latest_artifact(project_id: int, job: str):
        latest_build = GitlabUtils.get_latest_build(project_id, job)
        if not latest_build:
            return None
        return GitlabUtils.get_build_artifacts(project_id, latest_build['id'])
