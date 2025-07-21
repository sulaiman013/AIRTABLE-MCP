#!/usr/bin/env python3
"""
Enhanced Airtable MCP Server with Advanced Security and Filtering
================================================================

Security Enhancements:
- Formula injection protection
- Enhanced input validation
- Secure error handling
- Authentication framework
- Comprehensive logging sanitization
"""

import os
import asyncio
import logging
import hashlib
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

# Import enhanced validators with security improvements
from validators import AirtableValidator, ValidationError, SecurityError, SecurityUtils

# Load environment variables
load_dotenv()

# Set up enhanced logging with security considerations
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('airtable_mcp.log', encoding='utf-8')
    ]
)
logger = logging.getLogger(__name__)

# Security configuration validation
def validate_environment():
    """Validate required environment variables and security settings"""
    required_vars = ["AIRTABLE_API_KEY"]
    missing_vars = []
    
    for var in required_vars:
        if not os.getenv(var):
            missing_vars.append(var)
    
    if missing_vars:
        raise SecurityError(f"Missing required environment variables: {', '.join(missing_vars)}")
    
    # Validate API key format (basic check)
    api_key = os.getenv("AIRTABLE_API_KEY")
    if not api_key.startswith(('pat', 'key')):
        logger.warning("API key format doesn't match expected Airtable patterns")

# Validate environment on startup
try:
    validate_environment()
except SecurityError as e:
    logger.error(f"Environment validation failed: {e}")
    raise

# Initialize server
server = Server("airtable-mcp-server")

# Initialize Airtable API
api_key = os.getenv("AIRTABLE_API_KEY")
if not api_key:
    raise ValueError("AIRTABLE_API_KEY environment variable is required")

airtable = AirtableApi(api_key)

# Enhanced helper functions for data processing with security
def parse_date_filter(date_str: str) -> tuple:
    """Parse date strings like 'May 2024' or '2024-05' into date range with validation"""
    # Enhanced: Validate input first
    try:
        validated_date_str = AirtableValidator.validate_date_range(date_str)
    except (ValidationError, SecurityError) as e:
        logger.warning(f"Invalid date range format: {AirtableValidator.sanitize_for_logging(date_str)}")
        raise ValidationError(f"Invalid date range: {e}")
    
    # Handle month names
    months = {
        'january': 1, 'february': 2, 'march': 3, 'april': 4,
        'may': 5, 'june': 6, 'july': 7, 'august': 8,
        'september': 9, 'october': 10, 'november': 11, 'december': 12
    }
    
    date_str_lower = validated_date_str.lower()
    
    # Try to parse "Month Year" format
    for month_name, month_num in months.items():
        if month_name in date_str_lower:
            year_str = date_str_lower.replace(month_name, '').strip()
            try:
                year = int(year_str)
                if year < 1900 or year > 2100:  # Reasonable year bounds
                    raise ValidationError(f"Year out of reasonable range: {year}")
                
                start_date = datetime(year, month_num, 1)
                # Get last day of month
                if month_num == 12:
                    end_date = datetime(year + 1, 1, 1)
                else:
                    end_date = datetime(year, month_num + 1, 1)
                return start_date, end_date
            except ValueError as e:
                logger.warning(f"Failed to parse year from date string: {AirtableValidator.sanitize_for_logging(date_str)}")
                pass
    
    # Try ISO format YYYY-MM
    try:
        parts = validated_date_str.split('-')
        if len(parts) == 2:
            year, month = int(parts[0]), int(parts[1])
            
            # Validate ranges
            if year < 1900 or year > 2100:
                raise ValidationError(f"Year out of reasonable range: {year}")
            if month < 1 or month > 12:
                raise ValidationError(f"Month out of range: {month}")
            
            start_date = datetime(year, month, 1)
            if month == 12:
                end_date = datetime(year + 1, 1, 1)
            else:
                end_date = datetime(year, month + 1, 1)
            return start_date, end_date
    except (ValueError, IndexError):
        pass
    
    # Default to current month if parsing fails
    logger.info(f"Using default current month for unparseable date: {AirtableValidator.sanitize_for_logging(date_str)}")
    now = datetime.now()
    start_date = datetime(now.year, now.month, 1)
    if now.month == 12:
        end_date = datetime(now.year + 1, 1, 1)
    else:
        end_date = datetime(now.year, now.month + 1, 1)
    
    return start_date, end_date

def build_date_formula(field_name: str, start_date: datetime, end_date: datetime) -> str:
    """
    SECURITY ENHANCED: Build Airtable formula for date range filtering with injection protection
    """
    # CRITICAL FIX: Validate field name for safe formula usage
    try:
        safe_field_name = AirtableValidator.validate_field_name_for_formula(field_name)
    except (ValidationError, SecurityError) as e:
        logger.error(f"Field name validation failed for formula: {AirtableValidator.sanitize_for_logging(field_name)}")
        raise SecurityError(f"Invalid field name for formula: {e}")
    
    # Validate dates
    if not isinstance(start_date, datetime) or not isinstance(end_date, datetime):
        raise ValidationError("start_date and end_date must be datetime objects")
    
    if start_date >= end_date:
        raise ValidationError("start_date must be before end_date")
    
    # Format dates safely
    start_str = start_date.strftime("%Y-%m-%d")
    end_str = end_date.strftime("%Y-%m-%d")
    
    # Build formula with properly escaped field name
    # Use curly braces for field names as per Airtable formula syntax
    return f"AND(IS_AFTER({{{safe_field_name}}}, '{start_str}'), IS_BEFORE({{{safe_field_name}}}, '{end_str}'))"

def aggregate_records(records: List[Dict], operation: str, field: str) -> Any:
    """Aggregate records by operation with enhanced validation"""
    if not records:
        return 0 if operation in ['sum', 'count'] else None
    
    # Validate operation
    valid_operations = {'sum', 'count', 'avg', 'average', 'min', 'max'}
    if operation not in valid_operations:
        raise ValidationError(f"Invalid aggregation operation: {operation}")
    
    # Validate field name if needed for operation
    if operation != 'count' and field:
        try:
            AirtableValidator.validate_field_name(field)
        except (ValidationError, SecurityError) as e:
            logger.warning(f"Invalid field name for aggregation: {AirtableValidator.sanitize_for_logging(field)}")
            raise ValidationError(f"Invalid field name: {e}")
    
    values = []
    
    for record in records:
        if operation == 'count':
            continue  # Count doesn't need field values
        
        value = record.get('fields', {}).get(field)
        if value is not None:
            if isinstance(value, (int, float)):
                values.append(value)
            elif isinstance(value, str):
                try:
                    values.append(float(value))
                except ValueError:
                    logger.debug(f"Skipping non-numeric value in aggregation: {AirtableValidator.sanitize_for_logging(str(value)[:50])}")
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

# Enhanced authentication framework (placeholder for full implementation)
class AuthenticationHandler:
    """Basic authentication framework - extend as needed"""
    
    def __init__(self):
        self.session_timeout = 3600  # 1 hour
        self.active_sessions = {}
    
    def validate_session(self, session_id: Optional[str]) -> bool:
        """Validate session ID - placeholder for real authentication"""
        if not session_id:
            return False
        
        # In a real implementation, validate against secure session store
        # For now, just check format
        if len(session_id) < 16:
            return False
        
        return True
    
    def generate_session_id(self) -> str:
        """Generate secure session ID"""
        return SecurityUtils.generate_secure_session_id()

auth_handler = AuthenticationHandler()

@server.list_tools()
async def list_tools() -> List[Tool]:
    """List available tools with enhanced descriptions"""
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
                        "description": "The ID of the Airtable base (format: app + 14 characters)"
                    }
                },
                "required": ["base_id"]
            }
        ),
        Tool(
            name="search_records",
            description="Search and filter records with advanced options and security validation",
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
                        "description": "Airtable formula for filtering (optional, must be valid formula syntax)"
                    },
                    "search_field": {
                        "type": "string",
                        "description": "Field name to search in"
                    },
                    "search_value": {
                        "type": "string",
                        "description": "Value to search for (max 1000 characters)"
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
                        "description": "Maximum records to return (1-1000)",
                        "default": 100,
                        "minimum": 1,
                        "maximum": 1000
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
    """Handle tool calls with enhanced validation and security"""
    
    logger.info(f"Tool call: {name} with args: {AirtableValidator.sanitize_for_logging(arguments)}")
    
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
    
    except SecurityError as e:
        logger.warning(f"Security error in {name}: {str(e)}")
        return [TextContent(type="text", text=f"Security Error: Access denied - {str(e)}")]
    
    except ValidationError as e:
        logger.warning(f"Validation error in {name}: {str(e)}")
        return [TextContent(type="text", text=f"Validation Error: {str(e)}")]
    
    except Exception as e:
        # Enhanced error handling with sanitization
        sanitized_error = AirtableValidator.sanitize_error_message(e)
        logger.error(f"Error in {name}: {sanitized_error}")
        return [TextContent(type="text", text=f"Error: {sanitized_error}")]

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
        
        logger.info(f"Listed {len(result)} bases")
        return [TextContent(type="text", text=text)]
        
    except Exception as e:
        sanitized_error = AirtableValidator.sanitize_error_message(e)
        return [TextContent(type="text", text=f"Error listing bases: {sanitized_error}")]

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
        
        logger.info(f"Listed {len(result)} tables for base {base_id}")
        return [TextContent(type="text", text=text)]
        
    except Exception as e:
        sanitized_error = AirtableValidator.sanitize_error_message(e)
        return [TextContent(type="text", text=f"Error listing tables: {sanitized_error}")]

async def handle_search_records(arguments: Dict[str, Any]) -> Sequence[TextContent]:
    """Search records with enhanced security validation"""
    try:
        # Enhanced validation with new security methods
        base_id = AirtableValidator.validate_base_id(arguments.get("base_id"))
        table_id = AirtableValidator.validate_table_id(arguments.get("table_id"))
        max_records = AirtableValidator.validate_max_records(arguments.get("max_records", 100))
        
        table = airtable.table(base_id, table_id)
        
        # Build filter formula with enhanced security
        formulas = []
        
        # Custom formula validation
        if arguments.get("filter_by_formula"):
            validated_formula = AirtableValidator.validate_filter_formula(arguments["filter_by_formula"])
            if validated_formula:
                formulas.append(validated_formula)
        
        # Enhanced search filter validation
        if arguments.get("search_field") and arguments.get("search_value"):
            # Validate both field name and search value with new security methods
            search_field = AirtableValidator.validate_field_name_for_formula(arguments["search_field"])
            search_value = AirtableValidator.validate_search_value(arguments["search_value"])
            
            # Use FIND for partial matching with properly escaped values
            # Escape single quotes in search value
            escaped_search_value = search_value.replace("'", "''")
            formulas.append(f"FIND(LOWER('{escaped_search_value}'), LOWER({{{search_field}}}))")
        
        # Enhanced date range filter validation
        if arguments.get("date_field") and arguments.get("date_range"):
            try:
                date_field = AirtableValidator.validate_field_name_for_formula(arguments["date_field"])
                start_date, end_date = parse_date_filter(arguments["date_range"])
                date_formula = build_date_formula(date_field, start_date, end_date)
                formulas.append(date_formula)
            except (ValidationError, SecurityError) as e:
                logger.warning(f"Date filter validation failed: {e}")
                raise ValidationError(f"Invalid date filter: {e}")
        
        # Combine formulas safely
        formula = None
        if formulas:
            if len(formulas) == 1:
                formula = formulas[0]
            else:
                formula = f"AND({', '.join(formulas)})"
        
        # Validate fields list if provided
        fields_list = None
        if arguments.get("fields"):
            if not isinstance(arguments["fields"], list):
                raise ValidationError("fields must be a list")
            
            validated_fields = []
            for field in arguments["fields"]:
                validated_field = AirtableValidator.validate_field_name(field)
                validated_fields.append(validated_field)
            fields_list = validated_fields
        
        # Fetch records with validated parameters
        kwargs = {"max_records": max_records}
        if formula:
            kwargs["formula"] = formula
        if fields_list:
            kwargs["fields"] = fields_list
        
        records = table.all(**kwargs)
        
        # Format results with security considerations
        text = f"Found {len(records)} records"
        if formula:
            text += f" (filtered)"
        text += ":\n\n"
        
        for i, record in enumerate(records[:20], 1):  # Show first 20
            text += f"{i}. Record ID: {record['id']}\n"
            for field, value in record['fields'].items():
                if value:  # Only show non-empty fields
                    # Sanitize field values for display
                    display_value = str(value)
                    if len(display_value) > 200:
                        display_value = display_value[:200] + "...[TRUNCATED]"
                    text += f"   {field}: {display_value}\n"
            text += "\n"
        
        if len(records) > 20:
            text += f"... and {len(records) - 20} more records\n"
        
        logger.info(f"Search completed: {len(records)} records found for base {base_id}, table {table_id}")
        return [TextContent(type="text", text=text)]
        
    except (SecurityError, ValidationError) as e:
        # Re-raise security and validation errors
        raise
    except Exception as e:
        sanitized_error = AirtableValidator.sanitize_error_message(e)
        logger.error(f"Error searching records: {sanitized_error}")
        return [TextContent(type="text", text=f"Error searching records: {sanitized_error}")]

async def handle_aggregate_records(arguments: Dict[str, Any]) -> Sequence[TextContent]:
    """Aggregate records with enhanced validation"""
    try:
        # Enhanced validation
        base_id = AirtableValidator.validate_base_id(arguments.get("base_id"))
        table_id = AirtableValidator.validate_table_id(arguments.get("table_id"))
        operation = arguments.get("operation", "count")
        field = arguments.get("field")
        
        # Validate operation
        valid_operations = {"sum", "count", "avg", "average", "min", "max"}
        if operation not in valid_operations:
            raise ValidationError(f"Invalid operation: {operation}. Must be one of: {', '.join(valid_operations)}")
        
        # Validate field name if required
        if operation != "count" and field:
            field = AirtableValidator.validate_field_name(field)
        elif operation != "count" and not field:
            raise ValidationError(f"Field name is required for operation '{operation}'")
        
        table = airtable.table(base_id, table_id)
        
        # Build filter formula with enhanced validation
        formulas = []
        
        if arguments.get("filter_by_formula"):
            validated_formula = AirtableValidator.validate_filter_formula(arguments["filter_by_formula"])
            if validated_formula:
                formulas.append(validated_formula)
        
        # Enhanced date range filter
        if arguments.get("date_field") and arguments.get("date_range"):
            try:
                date_field = AirtableValidator.validate_field_name_for_formula(arguments["date_field"])
                start_date, end_date = parse_date_filter(arguments["date_range"])
                date_formula = build_date_formula(date_field, start_date, end_date)
                formulas.append(date_formula)
            except (ValidationError, SecurityError) as e:
                logger.warning(f"Date filter validation failed in aggregation: {e}")
                raise ValidationError(f"Invalid date filter: {e}")
        
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
        
        # Handle grouping with validation
        if arguments.get("group_by"):
            group_field = AirtableValidator.validate_field_name(arguments["group_by"])
            groups = {}
            
            for record in records:
                group_value = record.get('fields', {}).get(group_field, 'Unknown')
                # Convert group value to string for consistent handling
                group_key = str(group_value) if group_value is not None else 'Unknown'
                if group_key not in groups:
                    groups[group_key] = []
                groups[group_key].append(record)
            
            # Aggregate by group
            text = f"Aggregation by {group_field}:\n\n"
            total_result = 0
            group_count = 0
            
            for group_name, group_records in sorted(groups.items()):
                try:
                    result = aggregate_records(group_records, operation, field)
                    if result is not None:
                        text += f"{group_name}: {result}"
                        if operation in ['sum', 'count']:
                            text += f" ({operation})"
                            total_result += result
                            group_count += 1
                        text += "\n"
                except Exception as e:
                    logger.warning(f"Aggregation failed for group {group_name}: {AirtableValidator.sanitize_error_message(e)}")
                    text += f"{group_name}: Error - {AirtableValidator.sanitize_error_message(e)}\n"
            
            if operation in ['sum', 'count'] and group_count > 1:
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
        
        logger.info(f"Aggregation completed: {operation} on {len(records)} records for base {base_id}, table {table_id}")
        return [TextContent(type="text", text=text)]
        
    except (SecurityError, ValidationError) as e:
        # Re-raise security and validation errors
        raise
    except Exception as e:
        sanitized_error = AirtableValidator.sanitize_error_message(e)
        logger.error(f"Error aggregating records: {sanitized_error}")
        return [TextContent(type="text", text=f"Error aggregating records: {sanitized_error}")]

async def handle_get_field_values(arguments: Dict[str, Any]) -> Sequence[TextContent]:
    """Get distinct values from a field with enhanced validation"""
    try:
        base_id = AirtableValidator.validate_base_id(arguments.get("base_id"))
        table_id = AirtableValidator.validate_table_id(arguments.get("table_id"))
        field = AirtableValidator.validate_field_name(arguments.get("field"))
        unique = arguments.get("unique", True)
        
        # Validate unique parameter
        if not isinstance(unique, bool):
            unique = True
        
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
            # Convert to string for deduplication, then sort
            unique_values = list(set(str(v) for v in values))
            unique_values.sort()
            values = unique_values
        
        text = f"Values in field '{field}':\n"
        text += f"Total records: {len(records)}\n"
        text += f"Distinct values: {len(values) if unique else 'not calculated'}\n\n"
        
        # Display values with truncation for very long values
        display_limit = 50
        for i, value in enumerate(values[:display_limit]):
            display_value = str(value)
            if len(display_value) > 100:
                display_value = display_value[:100] + "...[TRUNCATED]"
            text += f"- {display_value}\n"
        
        if len(values) > display_limit:
            text += f"\n... and {len(values) - display_limit} more values\n"
        
        logger.info(f"Field values retrieved: {len(values)} values from field {field} for base {base_id}, table {table_id}")
        return [TextContent(type="text", text=text)]
        
    except (SecurityError, ValidationError) as e:
        # Re-raise security and validation errors
        raise
    except Exception as e:
        sanitized_error = AirtableValidator.sanitize_error_message(e)
        return [TextContent(type="text", text=f"Error getting field values: {sanitized_error}")]

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
                # Sanitize options for display
                try:
                    options_str = json.dumps(field.options, indent=2)
                    if len(options_str) > 500:
                        options_str = options_str[:500] + "...[TRUNCATED]"
                    text += f"  Options: {options_str}\n"
                except Exception as e:
                    text += f"  Options: [Could not serialize - {AirtableValidator.sanitize_error_message(e)}]\n"
            text += "\n"
        
        logger.info(f"Schema retrieved for table {table_id} in base {base_id}")
        return [TextContent(type="text", text=text)]
        
    except Exception as e:
        sanitized_error = AirtableValidator.sanitize_error_message(e)
        return [TextContent(type="text", text=f"Error getting table schema: {sanitized_error}")]

async def main():
    """Main entry point with enhanced error handling"""
    try:
        logger.info("Starting Enhanced Airtable MCP Server with Security Features...")
        logger.info("Security features: Formula injection protection, Enhanced validation, Secure logging")
        
        async with stdio_server() as (read_stream, write_stream):
            await server.run(
                read_stream,
                write_stream,
                server.create_initialization_options()
            )
    except Exception as e:
        sanitized_error = AirtableValidator.sanitize_error_message(e)
        logger.error(f"Server error: {sanitized_error}")
        raise

if __name__ == "__main__":
    asyncio.run(main())
