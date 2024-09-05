# Development Guide
The Development Guide establishes conventions that regular contributors are expected to follow on ScubaGoggles.

## Branching Strategy
We adhere to [GitHub flow](https://docs.github.com/en/get-started/using-github/github-flow) as closely as our specific constraints allow. In general, this means:
- Development is performed on short-lived features branches (see [Contributing Code](#contributing-code) for more details).
- There is only one primary branch, `main`. After review, changes are committed directly to main, rather than to long-lived develop or release branches.

There are exceptions to this, necessitated by the extensive review process the baseline documents themselves undergo, during which no baseline changes can be made.
To accommodate this, the development lifecycle on ScubaGoggles is as follows:
![image](/docs/images/scubagoggles_lifecycle.svg)


Baseline submission triggers a baseline freeze, at which point the following actions need to be performed:
1. Bump the code in `main` to the upcoming version (to reduce merge conflicts downstream).
2. Make a note of the last commit hash, to help in case of complications rebasing down the line.
3. Create a temporary protected branch dedicated to baseline changes that are slated for the next release.

A new release triggers the transition back to normal operations. At this time, the following actions need to be performed:
1. Pause development on main and perform functional testing.
2. Assuming the testing results are satisfactory, create the release off of `main`.
3. Rebase the temporary baseline branch with `main`.
4. Implement the baseline code issues created during the baseline freeze to get the release branch into a fully functional state.
5. Merge the baseline branch into `main`.
6. Delete the baseline branch.

## Branching Structure
See [Branching Structure Diagram](BRANCHINGSTRUCTURE.md) for a visual representation of the branch structure, both during a code freeze and otherwise.

## Creating Issues
All needed changes (e.g., new features, bug fixes) need to be tracked in an issue. When creating an issue:
1. Be sure to follow the template.
2. Add the appropriate labels (e.g., "bug," "enhancement").
3. Add the issue to the correct project.
4. Leave the milestone option blank; new issues will be triaged during sprint planning and assigned to an appropriate milestone.

## Contributing Code
### Step 1: Create a branch and implement changes
1. Open the corresponding issue. If no issue has been created for the intended change, first create one (see [Creating Issues](#creating-issues)).
2. Add yourself as the assignee on the issue. NOTE: Having just one assignee per issue is preferred.
3. Add the issue to the current milestone if it hasn't already been added.
4. Click the "Create a branch for this issue" button (see screenshot).
![image](https://github.com/user-attachments/assets/4dbaf33b-ff53-48b3-aa39-74c97094dfbc)
5. Ensure that the branch name follows the convention: "issue-number-short-description" and that the "short-description" is specific to that issue and not too vague.
For example, if you were to create a branch name for the issue in the screenshot, you might name it "341-update-testing-docs."
6. If this is a baseline change and we are currently in a baseline freeze: click the "Change Branch source" button and select the dedicated baseline changes branch.
Otherwise, leave this at the default (main).
![image](https://github.com/user-attachments/assets/e3cafc21-9400-44f5-b7ab-2a21e63772c1)
7. Make the needed changes in the branch. While doing that, watch out for scope creep! Resist the temptation to lump multiple issues together.
In some cases, there may be reasonable exceptions to this rule, but in general, GitHub flow encourages making quick, lightweight changes and short-lived feature branches.

### Step 2: Make a Pull Request
1. Open a new pull request for your branch. If you recently pushed to your branch, when you visit the GitHub repo in a web browser you'll see a suggestion to start a pull request.
![image](https://github.com/user-attachments/assets/e6de2e67-6fd6-4d30-8c5b-790151ea906b)


Otherwise, go to the "Pull requests" tab and click "New pull request"

2. In either case, ensure your branch is selected as the "head ref."
![image](https://github.com/user-attachments/assets/8b3c2e73-6b64-49bf-a993-797f4d975da3)
3. If this is a baseline change and we are in a baseline freeze, select the dedicated baseline change branch as the "base ref." Otherwise, leave it as its default of main.
![image](https://github.com/user-attachments/assets/0779cdbb-b888-463a-9cc8-35a16a1735ee)
4. Give the pull request a descriptive, human readable name, preferably describing an action in the imperative form.
For example, for the issue above you might name the pull request "Add smoke test documentation."
5. Add the PR to the correct project and the current milestone.
6. Follow the template!
    - Under motivation and context, if you're not sure what to put, you can just put "Closes #issue-number," e.g., "Closes #341."
This does two things: it makes it so that GitHub will automatically close the issue when the PR is merged and it lets the reviewers know where they can look for context.
NOTE: in order for GitHub to automatically close the issue, the "closes" statement needs to be the only thing on the line. For example: "Closes #341. Closes #342" won't work;
the two "closes" statements need to be on separate lines.
    - Check the pre-approval checklist. If you can't check all the boxes there, reconsider making the pull request now – that is a sign that the branch isn't ready to be merged yet.
7. Assign two reviewers. If unsure who to assign, bring up the issue in a team meeting for recommendations.
8. Update the status for both the issue and the PR to "In Review" when ready for review.

### Step 3: Closing Steps
1. Address review feedback. Only the reviewer should click the "Resolve conversation" button for the feedback; however, note that if the reviewer makes a suggested change and you click "Commit suggestion" GitHub will automatically resolve the conversation.
2. After both reviewers approve, one of the reviewers should merge the PR (selecting "squash and commit").
3. If this PR was merged to the dedicated baseline change branch, manually close any associated issues.
4. Delete the feature branch.
