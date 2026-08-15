# Project Management

## Task and Source Code Management

The project was managed using **Jira** and **GitHub** together. Jira was used for planning and tracking the development process, while GitHub was used for implementing, reviewing, and maintaining the corresponding source code.

### Jira

Jira was used for:

- dividing the project into epics, tasks, and subtasks;
- assigning responsibilities between team members;
- tracking task status and overall development progress;
- planning and organizing upcoming work;
- defining the scope and expected outcome of each implementation task;
- linking implementation work to the corresponding GitHub branch or pull request.

Where applicable, Jira task identifiers were included in GitHub branch names and commits.

Example:

```text
ASC-56-implement-analyze-command
```

### GitHub

GitHub was used for:

- maintaining the project source code;
- creating feature branches for individual Jira tasks;
- tracking implementation history through commits;
- reviewing and merging completed work through pull requests;
- storing the project documentation, tests, and configuration files;
- maintaining the final version of the project.

### Development Workflow

The typical development workflow was:

```text
Jira task created
        ↓
Feature branch created in GitHub
        ↓
Implementation and commits
        ↓
Testing and review
        ↓
Pull request / merge
        ↓
Jira task marked as Done
```

Using Jira and GitHub together provided complete traceability throughout the development process. Jira documented **what** was implemented and tracked the project's progress, while GitHub documented **how** each feature was implemented through branches, commits, pull requests, and the project's version history.
