# GitLab CI

Add this job to your `.gitlab-ci.yml`. It runs on merge requests, keeps the
reports as artifacts and fails the pipeline on high risk.

```yaml
diffguard:
  stage: test
  image: python:3.12
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
  variables:
    GIT_DEPTH: "0"          # DiffGuard needs the merge base
  script:
    - pip install --quiet diffguard-scan
    - diffguard scan --base "$CI_MERGE_REQUEST_DIFF_BASE_SHA" --fail-on never
        -o json=diffguard.json -o markdown=diffguard.md
    - diffguard gate diffguard.json --fail-on high
  artifacts:
    when: always
    paths: [diffguard.json, diffguard.md]
```

Until the package is on PyPI, install from GitHub instead:

```yaml
    - pip install --quiet "git+https://github.com/mostaphaelansari/Feature-to-Production-Autonomous-Flow@v0.2.0"
```

To block merging, enable **Settings → Merge requests → Pipelines must succeed**.

## Posting the report on the merge request

`diffguard.md` is ready to post as a note. With a project access token stored
in a masked variable `DIFFGUARD_TOKEN` (scope `api`), append:

```yaml
    - >
      curl --silent --fail --request POST
      --header "PRIVATE-TOKEN: $DIFFGUARD_TOKEN"
      --data-urlencode "body@diffguard.md"
      "$CI_API_V4_URL/projects/$CI_PROJECT_ID/merge_requests/$CI_MERGE_REQUEST_IID/notes"
```

## Tamper resistance

The job definition lives in the merge request's own `.gitlab-ci.yml`, so an
author can edit or delete it. If the gate must hold against the people it
checks, enforce it outside the project: a
[pipeline execution policy](https://docs.gitlab.com/ee/user/application_security/policies/pipeline_execution_policies.html)
or a compliance pipeline (GitLab Ultimate). See the README's
"Tamper resistance" section.
