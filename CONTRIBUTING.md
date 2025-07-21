# Contributing to Airtable MCP Server

First off, thank you for considering contributing to Airtable MCP Server! It's people like you that make this tool better for everyone.

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct:
- Be respectful and inclusive
- Welcome newcomers and help them get started
- Focus on constructive criticism
- Assume good intentions

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates.

When creating a bug report, include:
- **Clear title and description**
- **Steps to reproduce**
- **Expected behavior**
- **Actual behavior**
- **System information** (OS, Python version, MCP client)
- **Relevant logs** (sanitized of sensitive data)
- **Code samples** if applicable

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, include:
- **Use case** - Why is this needed?
- **Proposed solution** - How should it work?
- **Alternatives considered** - What other solutions did you think about?
- **Additional context** - mockups, examples, etc.

### Pull Requests

1. **Fork and Clone**
   ```bash
   git clone https://github.com/yourusername/airtable-mcp-server.git
   cd airtable-mcp-server
   ```

2. **Create a Branch**
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/issue-description
   ```

3. **Set Up Development Environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # Windows: venv\Scripts\activate
   pip install -r requirements.txt
   pip install -r requirements-dev.txt  # If available
   ```

4. **Make Your Changes**
   - Write clear, self-documenting code
   - Follow existing code style
   - Add/update tests as needed
   - Update documentation

5. **Test Your Changes**
   ```bash
   # Run tests
   pytest
   
   # Check code style
   pylint src/
   
   # Type checking
   mypy src/
   ```

6. **Commit Your Changes**
   ```bash
   git add .
   git commit -m "feat: add amazing feature
   
   - Detail 1
   - Detail 2
   
   Closes #123"
   ```

   Follow conventional commits:
   - `feat:` New feature
   - `fix:` Bug fix
   - `docs:` Documentation changes
   - `style:` Code style changes
   - `refactor:` Code refactoring
   - `test:` Test changes
   - `chore:` Build process or auxiliary tool changes

7. **Push and Create PR**
   ```bash
   git push origin feature/your-feature-name
   ```

## Development Guidelines

### Code Style

- Follow PEP 8
- Use type hints for all functions
- Maximum line length: 100 characters
- Use descriptive variable names
- Add docstrings to all public functions

Example:
```python
def search_records(
    base_id: str,
    table_id: str,
    search_field: Optional[str] = None,
    search_value: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Search for records in an Airtable table.
    
    Args:
        base_id: The Airtable base ID (format: appXXXXXXXXXXXXXX)
        table_id: The table ID (format: tblXXXXXXXXXXXXXX)
        search_field: Field name to search in
        search_value: Value to search for
        
    Returns:
        List of matching records
        
    Raises:
        ValidationError: If IDs are invalid
        AirtableError: If API request fails
    """
    # Implementation
```

### Testing

- Write tests for new features
- Maintain test coverage above 80%
- Use pytest fixtures for common test data
- Mock external API calls

Example test:
```python
def test_validate_base_id():
    """Test base ID validation."""
    # Valid ID
    assert AirtableValidator.validate_base_id("app12345678901234") == "app12345678901234"
    
    # Invalid ID
    with pytest.raises(ValidationError):
        AirtableValidator.validate_base_id("invalid")
```

### Security

- Never commit sensitive data (API keys, tokens)
- Validate all user inputs
- Sanitize error messages
- Follow security best practices in `validators.py`

### Documentation

- Update README.md for user-facing changes
- Add inline comments for complex logic
- Update API documentation
- Include examples for new features

## Project Structure

```
airtable-mcp-server/
├── src/
│   ├── __init__.py
│   ├── server.py          # Main MCP server
│   └── validators.py      # Input validation
├── tests/
│   ├── test_server.py
│   └── test_validators.py
├── .env.example          # Environment variable template
├── .gitignore
├── CONTRIBUTING.md       # This file
├── LICENSE
├── README.md
└── requirements.txt
```

## Release Process

1. Update version in relevant files
2. Update CHANGELOG.md
3. Create a pull request
4. After merge, tag the release
5. GitHub Actions will handle PyPI deployment

## Getting Help

- Check the [documentation](README.md)
- Look through [existing issues](https://github.com/yourusername/airtable-mcp-server/issues)
- Ask in [discussions](https://github.com/yourusername/airtable-mcp-server/discussions)
- Reach out to maintainers

## Recognition

Contributors will be recognized in:
- The README.md contributors section
- Release notes
- The project's Contributors page

Thank you for making Airtable MCP Server better! 🎉
