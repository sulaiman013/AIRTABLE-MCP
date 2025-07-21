# Airtable MCP Server

<div align="center">

![Airtable MCP Server](https://img.shields.io/badge/MCP-Airtable-blue)
![Python](https://img.shields.io/badge/Python-3.9+-green)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Status](https://img.shields.io/badge/Status-Production%20Ready-brightgreen)

An advanced Model Context Protocol (MCP) server that enables AI assistants to interact with Airtable databases through natural language. Features intelligent filtering, aggregation, and comprehensive security validation.

[Features](#features) • [Installation](#installation) • [Configuration](#configuration) • [Usage](#usage) • [Tools](#available-tools) • [Security](#security)

</div>

## 🚀 Features

- **Advanced Filtering**: Date range filtering, formula-based queries, and field-specific searches
- **Data Aggregation**: Sum, count, average, min/max operations with grouping support
- **Intelligent Search**: Natural language date parsing and partial text matching
- **Comprehensive Security**: Input validation, dangerous pattern detection, and sanitization
- **Schema Inspection**: Detailed table structure and field type information
- **Field Analysis**: Extract unique values and analyze field distributions
- **Error Handling**: Detailed logging and user-friendly error messages
- **No Rate Limiting**: Optimized for smooth, uninterrupted operations

## 📋 Prerequisites

- Python 3.9 or higher
- Airtable account with API key (Personal Access Token)
- MCP-compatible client (Claude Desktop, Cursor, VS Code, etc.)

## 🛠️ Installation

### Using `uv` (Recommended)

```bash
# Install with uv
uvx install airtable-mcp-server

# Or install from GitHub
uvx install git+https://github.com/yourusername/airtable-mcp-server.git
```

### Using `pip`

```bash
# Clone the repository
git clone https://github.com/yourusername/airtable-mcp-server.git
cd airtable-mcp-server

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## ⚙️ Configuration

### 1. Set up Airtable API Key

Create a `.env` file in the project root:

```env
AIRTABLE_API_KEY=patXXXXXXXXXXXXXX
```

To get your API key:
1. Go to [Airtable Account](https://airtable.com/account)
2. Generate a personal access token with appropriate scopes
3. Copy the token (starts with `pat`)

### 2. Configure MCP Client

#### Claude Desktop

Add to your Claude Desktop configuration:

```json
{
  "mcpServers": {
    "airtable": {
      "command": "python",
      "args": ["/path/to/airtable-mcp-server/server.py"],
      "env": {
        "AIRTABLE_API_KEY": "patXXXXXXXXXXXXXX"
      }
    }
  }
}
```

#### VS Code / Cursor

Add to `.vscode/mcp.json` or user settings:

```json
{
  "mcpServers": {
    "airtable": {
      "command": "uvx",
      "args": ["airtable-mcp-server"],
      "env": {
        "AIRTABLE_API_KEY": "patXXXXXXXXXXXXXX"
      }
    }
  }
}
```

## 🔧 Available Tools

### 1. `list_bases`
List all accessible Airtable bases.

**Example**: "Show me all my Airtable bases"

### 2. `list_tables`
List all tables in a specific base.

**Parameters**:
- `base_id` (required): The Airtable base ID

**Example**: "List tables in base appXXXXXXXXXXXXXX"

### 3. `search_records`
Search and filter records with advanced options.

**Parameters**:
- `base_id` (required): The Airtable base ID
- `table_id` (required): The table ID
- `filter_by_formula`: Airtable formula for filtering
- `search_field`: Field name to search in
- `search_value`: Value to search for
- `date_field`: Field name for date filtering
- `date_range`: Date range (e.g., "May 2024", "2024-05")
- `max_records`: Maximum records to return (default: 100)
- `fields`: Specific fields to return

**Example**: "Find all sales records from May 2024 where amount > 1000"

### 4. `aggregate_records`
Perform aggregation operations on records.

**Parameters**:
- `base_id` (required): The Airtable base ID
- `table_id` (required): The table ID
- `operation` (required): sum, count, avg, average, min, or max
- `field`: Field to aggregate (for sum/avg/min/max)
- `filter_by_formula`: Airtable formula for filtering
- `group_by`: Field to group results by
- `date_field`: Field name for date filtering
- `date_range`: Date range for filtering

**Example**: "Calculate total revenue by product category for Q2 2024"

### 5. `get_field_values`
Get distinct values from a field.

**Parameters**:
- `base_id` (required): The Airtable base ID
- `table_id` (required): The table ID
- `field` (required): Field name to get values from
- `unique`: Return only unique values (default: true)

**Example**: "Show me all unique customer names"

### 6. `get_table_schema`
Get detailed schema information about a table.

**Parameters**:
- `base_id` (required): The Airtable base ID
- `table_id` (required): The table ID

**Example**: "Show me the structure of the Orders table"

## 📝 Usage Examples

### Basic Queries

```
"List all my Airtable bases"
"Show tables in my CRM base"
"Find records where Status is 'Active'"
```

### Advanced Filtering

```
"Find all orders from May 2024 with amount greater than $1000"
"Search for customers with 'John' in their name"
"Show projects due this month"
```

### Aggregation Queries

```
"Calculate total sales by region"
"Count active projects by team"
"What's the average order value for premium customers?"
```

### Schema Exploration

```
"What fields are in the Customers table?"
"Show me all product categories in the inventory"
"Describe the Orders table structure"
```

## 🔐 Security

This server implements comprehensive security measures:

- **Input Validation**: Strict validation of all Airtable IDs and parameters
- **Pattern Detection**: Blocks potentially dangerous content (XSS, SQL injection attempts)
- **Data Sanitization**: Automatic sanitization of suspicious content
- **Error Handling**: Sanitized error messages prevent information leakage
- **Type Safety**: Strong typing prevents type confusion attacks
- **Rate Limiting**: Built-in protections against abuse (configurable)

See `validators.py` for implementation details.

## 🧪 Development

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src

# Run specific test
pytest tests/test_validators.py
```

### Local Development

```bash
# Install in development mode
pip install -e .

# Run the server locally
python src/server.py

# Enable debug logging
export MCP_DEBUG=true
python src/server.py
```

## 📊 Logging

Logs are written to:
- Console output (configurable level)
- `airtable_mcp.log` file (UTF-8 encoded)

Configure logging level:
```python
# In server.py
logging.basicConfig(level=logging.DEBUG)  # For verbose output
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 🐛 Troubleshooting

### Common Issues

**"Base ID not found"**
- Ensure your API key has access to the base
- Verify the base ID format (starts with `app`)

**"Invalid table ID"**
- Check table ID format (starts with `tbl`)
- Confirm table exists in the specified base

**"Authentication failed"**
- Verify your API key is correct
- Check if the token has required scopes

**Date filtering not working**
- Ensure date field contains proper date values
- Use supported formats: "May 2024", "2024-05", "2024-05-15"

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Airtable](https://airtable.com) for their excellent API
- [Anthropic](https://anthropic.com) for the Model Context Protocol
- [pyairtable](https://github.com/gtalarico/pyairtable) for the Python SDK
- MCP community for inspiration and best practices

## 📚 Resources

- [Model Context Protocol Documentation](https://modelcontextprotocol.io)
- [Airtable API Documentation](https://airtable.com/developers/web/api/introduction)
- [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk)
- [Airtable Formula Reference](https://support.airtable.com/docs/formula-field-reference)

---

<div align="center">
Made with ❤️ for the MCP community
</div>
