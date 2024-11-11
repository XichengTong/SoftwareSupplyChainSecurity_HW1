# Contributing to Software Supply Chain Security Verification

The following is a set of guidelines for contributing to this project. These are mostly guidelines, not strict rules. 
Use your best judgment, and feel free to propose changes by opening a pull request.

## How to Contribute

### Pull Requests
- **Branching**: Create a new branch for each feature or bug fix. Use descriptive branch names such as `feature/new-feature` or `bugfix/issue-123`.
- **Description**: Provide a clear and concise description of the changes you are proposing, including the motivation behind them and any relevant issue numbers.
- **Checklist**:
  - Ensure your code adheres to the style guidelines and is thoroughly documented.
  - Make sure all tests pass before submitting a pull request.
  - Include any necessary tests for new features or bug fixes.
- **Template**: Fill out the pull request template with all relevant information, such as what problem the change addresses, testing steps, and any dependencies.
- **Review Process**: Be prepared to respond to review comments and make the necessary changes. This process helps maintain code quality and consistency.

### Reporting Issues
- **Bug Reports**: If you find a bug, create an issue with a descriptive title. Include:
  - Steps to reproduce the issue.
  - Expected and actual behavior.
  - Any error messages, logs, or screenshots that could help in diagnosing the problem.
- **Feature Requests**: If you have an idea for an enhancement, provide:
  - A clear title and description of the proposed feature.
  - The motivation behind the feature and how it will improve the project.
- **Issue Template**: Use the provided issue template to make sure all necessary details are included.

### Code Style Guidelines
- Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) for Python code style.
- Ensure code is clean, well-commented, and easy to understand.
- Consistently use meaningful variable and function names.

### Testing Requirements
- **Test Coverage**: Write tests for all new features and bug fixes. This includes unit tests for individual functions and integration tests where applicable.
- **Testing Tools**: Use `pytest` or another recommended testing framework to ensure consistency.
- **Running Tests**: Before submitting a pull request, run all tests locally to verify that nothing is broken. Use the command:
  ```sh
  pytest tests/
  ```
- **Continuous Integration**: Ensure that your changes do not break the build or tests in the CI pipeline. 
Check the status of your pull request once submitted to make sure all tests pass in the CI environment.

### Contributor Expectations
- Be respectful and collaborative.
- Communicate any challenges or questions that arise while contributing.
- Respond to review comments and be open to suggestions for improving your contribution.
