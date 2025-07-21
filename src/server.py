#!/usr/bin/env python3
"""
Enhanced Airtable MCP Server with Advanced Filtering and Aggregation
No rate limiting for smooth operation
"""

import os
import asyncio
import logging
from typing import Any, Dict, List, Optional, Sequence
from datetime import datetime, date
import json

from mcp.server import Server
from mcp.types import (
    Tool,
    TextContent,
    CallToolRequest,
    CallToolResult,
    ListToolsRequest,
    ListToolsResult,
)
from mcp.server.stdio import stdio_server
from pyairtable import Api as AirtableApi
# Note: pyairtable formulas are constructed as strings, not using formula helpers
from dotenv import load_dotenv

# Import validators only
from validators import AirtableValidator, ValidationError

# Load environment variables
load_dotenv()

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('airtable_mcp.log', encoding='utf-8')
    ]
)
logger = logging.getLogger(__name__)

# Initialize server
server = Server("airtable-mcp-server")

# Initialize Airtable API
api_key = os.getenv("AIRTABLE_API_KEY")
if not api_key:
    raise ValueError("AIRTABLE_API_KEY environment variable is required")

airtable = AirtableApi(api_key)

# Helper functions for data processing
def parse_date_filter(date_str: str) -> tuple:
    """Parse date strings like 'May 2024' or '2024-05' into date range"""
    # Handle month names
    months = {
        'january': 1, 'february': 2, 'march': 3, 'april': 4,
        'may': 5, 'june': 6, 'july': 7, 'august': 8,
        'september': 9, 'october': 10, 'november': 11, 'december': 12
    }
    
    date_str_lower = date_str.lower()
    
    # Try to parse "Month Year" format
    for month_name, month_num in months.items():
        if month_name in date_str_lower:
            year_str = date_str_lower.replace(month_name, '').strip()
            try:
                year = int(year_str)
                start_date = datetime(year, month_num, 1)
                # Get last day of month
                if month_num == 12:
                    end_date = datetime(year + 1, 1, 1)
                else:
                    end_date = datetime(year, month_num + 1, 1)
                return start_date, end_date
            except:
                pass
    
    # Try ISO format YYYY-MM
    try:
        parts = date_str.split('-')
        if len(parts) == 2:
            year, month = int(parts[0]), int(parts[1])
            start_date = datetime(year, month, 1)
            if month == 12:
                end_date = datetime(year + 1, 1, 1)
            else:
                end_date = datetime(year, month + 1, 1)
            return start_date, end_date
    except:
        pass
    
    # Default to current month
    now = datetime.now()
    start_date = datetime(now.year, now.month, 1)
    if now.month == 12:
        end_date = datetime(now.year + 1, 1, 1)
    else:
        end_date = datetime(now.year, now.month + 1, 1)
    
    return start_date, end_date

def build_date_formula(field_name: str, start_date: datetime, end_date: datetime) -> str:
    """Build Airtable formula for date range filtering"""
    start_str = start_date.strftime("%Y-%m-%d")
    end_str = end_date.strftime("%Y-%m-%d")
    
    return f"AND(IS_AFTER({{{field_name}}}, '{start_str}'), IS_BEFORE({{{field_name}}}, '{end_str}'))"

def aggregate_records(records: List[Dict], operation: str, field: str) -> Any:
    """Aggregate records by operation (sum, count, avg, etc.)"""
    values = []
    
    for record in records:
        value = record.get('fields', {}).get(field)
        if value is not None:
            if isinstance(value, (int, float)):
                values.append(value)
            elif isinstance(value, str):
                try:
                    values.append(float(value))
                except:
                    pass
    
    if operation == 'sum':
        return sum(values)
    elif operation == 'count':
        return len(records)
    elif operation == 'avg' or operation == 'average':
        return sum(values) / len(values) if values else 0
    elif operation == 'min':
        return min(values) if values else None
    elif operation == 'max':
        return max(values) if values else None
    
    return None

@server.list_tools()
async def list_tools() -> List[Tool]:
    """List available tools"""
    return [
        Tool(
            name="list_bases",
            description="List all accessible Airtable bases",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        ),
        Tool(
            name="list_tables",
            description="List all tables in a specific base",
            inputSchema={
                "type": "object",
                "properties": {
                    "base_id": {
                        "type": "string",
                        "description": "The ID of the Airtable base"
                    }
                },
                "required": ["base_id"]
            }
        ),
        Tool(
            name="search_records",
            description="Search and filter records with advanced options",
            inputSchema={
                "type": "object",
                "properties": {
                    "base_id": {
                        "type": "string",
                        "description": "The ID of the Airtable base"
                    },
                    "table_id": {
                        "type": "string",
                        "description": "The ID of the table"
                    },
                    "filter_by_formula": {
                        "type": "string",
                        "description": "Airtable formula for filtering (optional)"
                    },
                    "search_field": {
                        "type": "string",
                        "description": "Field name to search in"
                    },
                    "search_value": {
                        "type": "string",
                        "description": "Value to search for"
                    },
                    "date_field": {
                        "type": "string",
                        "description": "Field name for date filtering"
                    },
                    "date_range": {
                        "type": "string",
                        "description": "Date range (e.g., 'May 2024', '2024-05')"
                    },
                    "max_records": {
                        "type": "integer",
                        "description": "Maximum records to return",
                        "default": 100
                    },
                    "fields": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Specific fields to return"
                    }
                },
                "required": ["base_id", "table_id"]
            }
        ),
        Tool(
            name="aggregate_records",
            description="Aggregate data with sum, count, average operations",
            inputSchema={
                "type": "object",
                "properties": {
                    "base_id": {
                        "type": "string",
                        "description": "The ID of the Airtable base"
                    },
                    "table_id": {
                        "type": "string",
                        "description": "The ID of the table"
                    },
                    "operation": {
                        "type": "string",
                        "enum": ["sum", "count", "avg", "average", "min", "max"],
                        "description": "Aggregation operation"
                    },
                    "field": {
                        "type": "string",
                        "description": "Field to aggregate (for sum/avg/min/max)"
                    },
                    "filter_by_formula": {
                        "type": "string",
                        "description": "Airtable formula for filtering"
                    },
                    "group_by": {
                        "type": "string",
                        "description": "Field to group results by"
                    },
                    "date_field": {
                        "type": "string",
                        "description": "Field name for date filtering"
                    },
                    "date_range": {
                        "type": "string",
                        "description": "Date range (e.g., 'May 2024')"
                    }
                },
                "required": ["base_id", "table_id", "operation"]
            }
        ),
        Tool(
            name="get_field_values",
            description="Get distinct values from a field (useful for finding names, categories, etc.)",
            inputSchema={
                "type": "object",
                "properties": {
                    "base_id": {
                        "type": "string",
                        "description": "The ID of the Airtable base"
                    },
                    "table_id": {
                        "type": "string",
                        "description": "The ID of the table"
                    },
                    "field": {
                        "type": "string",
                        "description": "Field name to get values from"
                    },
                    "unique": {
                        "type": "boolean",
                        "description": "Return only unique values",
                        "default": True
                    }
                },
                "required": ["base_id", "table_id", "field"]
            }
        ),
        Tool(
            name="get_table_schema",
            description="Get detailed schema information about a table",
            inputSchema={
                "type": "object",
                "properties": {
                    "base_id": {
                        "type": "string",
                        "description": "The ID of the Airtable base"
                    },
                    "table_id": {
                        "type": "string",
                        "description": "The ID of the table"
                    }
                },
                "required": ["base_id", "table_id"]
            }
        )
    ]

@server.call_tool()
async def call_tool(name: str, arguments: Dict[str, Any]) -> Sequence[TextContent]:
    """Handle tool calls with validation"""
    
    logger.info(f"Tool call: {name}")
    
    try:
        if name == "list_bases":
            result = await handle_list_bases()
        
        elif name == "list_tables":
            base_id = AirtableValidator.validate_base_id(arguments.get("base_id"))
            result = await handle_list_tables(base_id)
        
        elif name == "search_records":
            result = await handle_search_records(arguments)
        
        elif name == "aggregate_records":
            result = await handle_aggregate_records(arguments)
        
        elif name == "get_field_values":
            result = await handle_get_field_values(arguments)
        
        elif name == "get_table_schema":
            base_id = AirtableValidator.validate_base_id(arguments.get("base_id"))
            table_id = AirtableValidator.validate_table_id(arguments.get("table_id"))
            result = await handle_get_table_schema(base_id, table_id)
        
        else:
            raise ValidationError(f"Unknown tool: {name}")
        
        return result
    
    except ValidationError as e:
        logger.warning(f"Validation error in {name}: {str(e)}")
        return [TextContent(type="text", text=f"Validation Error: {str(e)}")]
    
    except Exception as e:
        logger.error(f"Error in {name}: {str(e)}")
        return [TextContent(type="text", text=f"Error: {str(e)}")]

async def handle_list_bases() -> Sequence[TextContent]:
    """List all accessible Airtable bases"""
    try:
        bases = airtable.bases()
        result = []
        for base in bases:
            result.append({
                "id": base.id,
                "name": base.name,
                "permission_level": getattr(base, 'permission_level', 'unknown')
            })
        
        text = f"Found {len(result)} accessible bases:\n"
        text += "\n".join([f"- {b['name']} (ID: {b['id']})" for b in result])
        
        return [TextContent(type="text", text=text)]
        
    except Exception as e:
        return [TextContent(type="text", text=f"Error listing bases: {str(e)}")]

async def handle_list_tables(base_id: str) -> Sequence[TextContent]:
    """List tables in a base"""
    try:
        base = airtable.base(base_id)
        schema = base.schema()
        
        result = []
        for table in schema.tables:
            result.append({
                "id": table.id,
                "name": table.name,
                "description": getattr(table, 'description', ''),
                "field_count": len(table.fields)
            })
        
        text = f"Found {len(result)} tables in base:\n"
        text += "\n".join([f"- {t['name']} (ID: {t['id']}) - {t['field_count']} fields" for t in result])
        
        return [TextContent(type="text", text=text)]
        
    except Exception as e:
        return [TextContent(type="text", text=f"Error listing tables: {str(e)}")]

async def handle_search_records(arguments: Dict[str, Any]) -> Sequence[TextContent]:
    """Search records with advanced filtering"""
    try:
        base_id = AirtableValidator.validate_base_id(arguments.get("base_id"))
        table_id = AirtableValidator.validate_table_id(arguments.get("table_id"))
        max_records = arguments.get("max_records", 100)
        
        table = airtable.table(base_id, table_id)
        
        # Build filter formula
        formulas = []
        
        # Custom formula
        if arguments.get("filter_by_formula"):
            formulas.append(arguments["filter_by_formula"])
        
        # Search filter
        if arguments.get("search_field") and arguments.get("search_value"):
            search_field = arguments["search_field"]
            search_value = arguments["search_value"]
            # Use FIND for partial matching
            formulas.append(f"FIND(LOWER('{search_value}'), LOWER({{{search_field}}}))")
        
        # Date range filter
        if arguments.get("date_field") and arguments.get("date_range"):
            start_date, end_date = parse_date_filter(arguments["date_range"])
            date_formula = build_date_formula(arguments["date_field"], start_date, end_date)
            formulas.append(date_formula)
        
        # Combine formulas
        formula = None
        if formulas:
            if len(formulas) == 1:
                formula = formulas[0]
            else:
                formula = f"AND({', '.join(formulas)})"
        
        # Fetch records
        kwargs = {"max_records": max_records}
        if formula:
            kwargs["formula"] = formula
        if arguments.get("fields"):
            kwargs["fields"] = arguments["fields"]
        
        records = table.all(**kwargs)
        
        # Format results
        text = f"Found {len(records)} records"
        if formula:
            text += f" (filtered)"
        text += ":\n\n"
        
        for i, record in enumerate(records[:20], 1):  # Show first 20
            text += f"{i}. Record ID: {record['id']}\n"
            for field, value in record['fields'].items():
                if value:  # Only show non-empty fields
                    text += f"   {field}: {value}\n"
            text += "\n"
        
        if len(records) > 20:
            text += f"... and {len(records) - 20} more records\n"
        
        return [TextContent(type="text", text=text)]
        
    except Exception as e:
        return [TextContent(type="text", text=f"Error searching records: {str(e)}")]

async def handle_aggregate_records(arguments: Dict[str, Any]) -> Sequence[TextContent]:
    """Aggregate records with various operations"""
    try:
        base_id = AirtableValidator.validate_base_id(arguments.get("base_id"))
        table_id = AirtableValidator.validate_table_id(arguments.get("table_id"))
        operation = arguments.get("operation", "count")
        field = arguments.get("field")
        
        table = airtable.table(base_id, table_id)
        
        # Build filter formula
        formulas = []
        
        if arguments.get("filter_by_formula"):
            formulas.append(arguments["filter_by_formula"])
        
        # Date range filter
        if arguments.get("date_field") and arguments.get("date_range"):
            start_date, end_date = parse_date_filter(arguments["date_range"])
            date_formula = build_date_formula(arguments["date_field"], start_date, end_date)
            formulas.append(date_formula)
        
        # Combine formulas
        formula = None
        if formulas:
            if len(formulas) == 1:
                formula = formulas[0]
            else:
                formula = f"AND({', '.join(formulas)})"
        
        # Fetch all matching records
        kwargs = {}
        if formula:
            kwargs["formula"] = formula
        
        records = table.all(**kwargs)
        
        # Handle grouping
        if arguments.get("group_by"):
            group_field = arguments["group_by"]
            groups = {}
            
            for record in records:
                group_value = record.get('fields', {}).get(group_field, 'Unknown')
                if group_value not in groups:
                    groups[group_value] = []
                groups[group_value].append(record)
            
            # Aggregate by group
            text = f"Aggregation by {group_field}:\n\n"
            total_result = 0
            
            for group_name, group_records in sorted(groups.items()):
                result = aggregate_records(group_records, operation, field)
                if result is not None:
                    text += f"{group_name}: {result}"
                    if operation in ['sum', 'count']:
                        text += f" ({operation})"
                        total_result += result
                    text += "\n"
            
            if operation in ['sum', 'count'] and len(groups) > 1:
                text += f"\nTotal: {total_result}\n"
            
        else:
            # Single aggregation
            result = aggregate_records(records, operation, field)
            
            text = f"Aggregation result:\n"
            text += f"Operation: {operation}\n"
            if field:
                text += f"Field: {field}\n"
            text += f"Records processed: {len(records)}\n"
            text += f"Result: {result}\n"
        
        return [TextContent(type="text", text=text)]
        
    except Exception as e:
        return [TextContent(type="text", text=f"Error aggregating records: {str(e)}")]

async def handle_get_field_values(arguments: Dict[str, Any]) -> Sequence[TextContent]:
    """Get distinct values from a field"""
    try:
        base_id = AirtableValidator.validate_base_id(arguments.get("base_id"))
        table_id = AirtableValidator.validate_table_id(arguments.get("table_id"))
        field = arguments.get("field")
        unique = arguments.get("unique", True)
        
        table = airtable.table(base_id, table_id)
        
        # Fetch records with only the specified field
        records = table.all(fields=[field])
        
        values = []
        for record in records:
            value = record.get('fields', {}).get(field)
            if value is not None:
                if isinstance(value, list):
                    values.extend(value)
                else:
                    values.append(value)
        
        if unique:
            values = list(set(str(v) for v in values))
            values.sort()
        
        text = f"Values in field '{field}':\n"
        text += f"Total records: {len(records)}\n"
        text += f"Distinct values: {len(values) if unique else 'not calculated'}\n\n"
        
        for value in values[:50]:  # Show first 50
            text += f"- {value}\n"
        
        if len(values) > 50:
            text += f"\n... and {len(values) - 50} more values\n"
        
        return [TextContent(type="text", text=text)]
        
    except Exception as e:
        return [TextContent(type="text", text=f"Error getting field values: {str(e)}")]

async def handle_get_table_schema(base_id: str, table_id: str) -> Sequence[TextContent]:
    """Get detailed schema information about a table"""
    try:
        base = airtable.base(base_id)
        schema = base.schema()
        
        # Find the specific table
        target_table = None
        for table in schema.tables:
            if table.id == table_id:
                target_table = table
                break
        
        if not target_table:
            return [TextContent(type="text", text=f"Table {table_id} not found")]
        
        text = f"Table Schema: {target_table.name}\n"
        text += f"Table ID: {target_table.id}\n"
        text += f"Description: {getattr(target_table, 'description', 'No description')}\n"
        text += f"\nFields ({len(target_table.fields)}):\n\n"
        
        for field in target_table.fields:
            text += f"- {field.name}\n"
            text += f"  Type: {field.type}\n"
            text += f"  ID: {field.id}\n"
            if hasattr(field, 'options') and field.options:
                text += f"  Options: {json.dumps(field.options, indent=2)}\n"
            text += "\n"
        
        return [TextContent(type="text", text=text)]
        
    except Exception as e:
        return [TextContent(type="text", text=f"Error getting table schema: {str(e)}")]

async def main():
    """Main entry point"""
    try:
        logger.info("Starting Enhanced Airtable MCP Server (No Rate Limiting)...")
        
        async with stdio_server() as (read_stream, write_stream):
            await server.run(
                read_stream,
                write_stream,
                server.create_initialization_options()
            )
    except Exception as e:
        logger.error(f"Server error: {e}")
        raise

if __name__ == "__main__":
    asyncio.run(main())