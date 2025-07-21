#!/usr/bin/env python3
"""
Input Validation and Sanitization for Airtable MCP Server
=========================================================

This module provides comprehensive input validation to prevent:
- Malicious inputs
- Invalid Airtable ID formats
- Data injection attacks
- Type confusion attacks
- Out-of-range values
"""

import re
import logging
from typing import Any, Dict, List, Optional, Union
from datetime import datetime

logger = logging.getLogger(__name__)

class ValidationError(Exception):
    """Custom exception for validation errors"""
    pass

class AirtableValidator:
    """Comprehensive validator for Airtable MCP inputs"""
    
    # Airtable ID patterns
    BASE_ID_PATTERN = re.compile(r'^app[a-zA-Z0-9]{14}$')
    TABLE_ID_PATTERN = re.compile(r'^tbl[a-zA-Z0-9]{14}$')
    RECORD_ID_PATTERN = re.compile(r'^rec[a-zA-Z0-9]{14}$')
    FIELD_ID_PATTERN = re.compile(r'^fld[a-zA-Z0-9]{14}$')
    VIEW_ID_PATTERN = re.compile(r'^viw[a-zA-Z0-9]{14}$')
    
    # Security limits
    MAX_RECORDS = 1000
    MAX_FIELD_NAME_LENGTH = 200
    MAX_TEXT_FIELD_LENGTH = 100000  # Airtable's limit
    MAX_FILTER_FORMULA_LENGTH = 5000
    
    # Dangerous patterns to block
    DANGEROUS_PATTERNS = [
        re.compile(r'<script[^>]*>', re.IGNORECASE),
        re.compile(r'javascript:', re.IGNORECASE),
        re.compile(r'on\w+\s*=', re.IGNORECASE),
        re.compile(r'eval\s*\(', re.IGNORECASE),
        re.compile(r'expression\s*\(', re.IGNORECASE),
    ]
    
    @classmethod
    def validate_base_id(cls, base_id: Any) -> str:
        """Validate Airtable base ID format with strict type checking"""
        if base_id is None:
            raise ValidationError("Base ID cannot be None")
        
        if not isinstance(base_id, str):
            raise ValidationError(f"Base ID must be a string, got {type(base_id).__name__}: {base_id}")
        
        if len(base_id) == 0:
            raise ValidationError("Base ID cannot be empty")
        
        if not cls.BASE_ID_PATTERN.match(base_id):
            raise ValidationError(f"Invalid base ID format: {base_id}. Must be 'app' + 14 alphanumeric characters")
        
        return base_id
    
    @classmethod
    def validate_table_id(cls, table_id: Any) -> str:
        """Validate Airtable table ID format with strict type checking"""
        if table_id is None:
            raise ValidationError("Table ID cannot be None")
        
        if not isinstance(table_id, str):
            raise ValidationError(f"Table ID must be a string, got {type(table_id).__name__}: {table_id}")
        
        if len(table_id) == 0:
            raise ValidationError("Table ID cannot be empty")
        
        if not cls.TABLE_ID_PATTERN.match(table_id):
            raise ValidationError(f"Invalid table ID format: {table_id}. Must be 'tbl' + 14 alphanumeric characters")
        
        return table_id
    
    @classmethod
    def validate_record_id(cls, record_id: Any) -> str:
        """Validate Airtable record ID format with strict type checking"""
        if record_id is None:
            raise ValidationError("Record ID cannot be None")
        
        if not isinstance(record_id, str):
            raise ValidationError(f"Record ID must be a string, got {type(record_id).__name__}: {record_id}")
        
        if len(record_id) == 0:
            raise ValidationError("Record ID cannot be empty")
        
        if not cls.RECORD_ID_PATTERN.match(record_id):
            raise ValidationError(f"Invalid record ID format: {record_id}. Must be 'rec' + 14 alphanumeric characters")
        
        return record_id
    
    @classmethod
    def validate_max_records(cls, max_records: Any) -> int:
        """Validate max_records parameter"""
        if max_records is None:
            return 100  # Default value
        
        if isinstance(max_records, str):
            try:
                max_records = int(max_records)
            except ValueError:
                raise ValidationError(f"max_records must be a number, got: {max_records}")
        
        if not isinstance(max_records, int):
            raise ValidationError(f"max_records must be an integer, got {type(max_records).__name__}")
        
        if max_records < 1:
            raise ValidationError(f"max_records must be at least 1, got {max_records}")
        
        if max_records > cls.MAX_RECORDS:
            logger.warning(f"max_records {max_records} exceeds limit, capping at {cls.MAX_RECORDS}")
            return cls.MAX_RECORDS
        
        return max_records
    
    @classmethod
    def validate_field_name(cls, field_name: str) -> str:
        """Validate field name"""
        if not isinstance(field_name, str):
            raise ValidationError(f"Field name must be a string, got {type(field_name).__name__}")
        
        if len(field_name) == 0:
            raise ValidationError("Field name cannot be empty")
        
        if len(field_name) > cls.MAX_FIELD_NAME_LENGTH:
            raise ValidationError(f"Field name too long: {len(field_name)} > {cls.MAX_FIELD_NAME_LENGTH}")
        
        # Check for dangerous patterns
        for pattern in cls.DANGEROUS_PATTERNS:
            if pattern.search(field_name):
                raise ValidationError(f"Field name contains potentially dangerous content: {field_name}")
        
        return field_name.strip()
    
    @classmethod
    def validate_field_value(cls, field_name: str, value: Any) -> Any:
        """Validate and sanitize field value"""
        if value is None:
            return None
        
        # Handle different field types
        if isinstance(value, str):
            return cls._validate_text_value(field_name, value)
        elif isinstance(value, (int, float)):
            return cls._validate_numeric_value(field_name, value)
        elif isinstance(value, bool):
            return value
        elif isinstance(value, list):
            return cls._validate_array_value(field_name, value)
        elif isinstance(value, dict):
            return cls._validate_object_value(field_name, value)
        else:
            # Convert to string for unknown types
            logger.warning(f"Unknown field type for {field_name}: {type(value)}, converting to string")
            return cls._validate_text_value(field_name, str(value))
    
    @classmethod
    def _validate_text_value(cls, field_name: str, value: str) -> str:
        """Validate text field value"""
        if len(value) > cls.MAX_TEXT_FIELD_LENGTH:
            raise ValidationError(f"Text field '{field_name}' too long: {len(value)} > {cls.MAX_TEXT_FIELD_LENGTH}")
        
        # Check for dangerous patterns
        for pattern in cls.DANGEROUS_PATTERNS:
            if pattern.search(value):
                logger.warning(f"Potentially dangerous content detected in field '{field_name}': {pattern.pattern}")
                # Sanitize instead of rejecting
                value = pattern.sub('[SANITIZED]', value)
        
        return value
    
    @classmethod
    def _validate_numeric_value(cls, field_name: str, value: Union[int, float]) -> Union[int, float]:
        """Validate numeric field value"""
        # Check for reasonable numeric limits
        if abs(value) > 1e15:  # Very large numbers
            raise ValidationError(f"Numeric value for '{field_name}' too large: {value}")
        
        return value
    
    @classmethod
    def _validate_array_value(cls, field_name: str, value: List[Any]) -> List[Any]:
        """Validate array field value"""
        if len(value) > 1000:  # Reasonable limit for arrays
            raise ValidationError(f"Array field '{field_name}' too large: {len(value)} items")
        
        # Validate each item in the array
        return [cls.validate_field_value(f"{field_name}[{i}]", item) for i, item in enumerate(value)]
    
    @classmethod
    def _validate_object_value(cls, field_name: str, value: Dict[str, Any]) -> Dict[str, Any]:
        """Validate object field value"""
        if len(value) > 100:  # Reasonable limit for object properties
            raise ValidationError(f"Object field '{field_name}' too large: {len(value)} properties")
        
        # Validate each property
        validated = {}
        for key, val in value.items():
            validated_key = cls.validate_field_name(key)
            validated_val = cls.validate_field_value(f"{field_name}.{key}", val)
            validated[validated_key] = validated_val
        
        return validated
    
    @classmethod
    def validate_fields_dict(cls, fields: Dict[str, Any]) -> Dict[str, Any]:
        """Validate a complete fields dictionary for record creation/update"""
        if not isinstance(fields, dict):
            raise ValidationError(f"Fields must be a dictionary, got {type(fields).__name__}")
        
        if len(fields) == 0:
            raise ValidationError("Fields dictionary cannot be empty")
        
        if len(fields) > 200:  # Airtable's field limit per table
            raise ValidationError(f"Too many fields: {len(fields)} > 200")
        
        validated = {}
        for field_name, value in fields.items():
            validated_name = cls.validate_field_name(field_name)
            validated_value = cls.validate_field_value(validated_name, value)
            validated[validated_name] = validated_value
        
        return validated
    
    @classmethod
    def validate_filter_formula(cls, formula: Optional[str]) -> Optional[str]:
        """Validate Airtable filter formula"""
        if formula is None:
            return None
        
        if not isinstance(formula, str):
            raise ValidationError(f"Filter formula must be a string, got {type(formula).__name__}")
        
        if len(formula) > cls.MAX_FILTER_FORMULA_LENGTH:
            raise ValidationError(f"Filter formula too long: {len(formula)} > {cls.MAX_FILTER_FORMULA_LENGTH}")
        
        # Basic sanity checks for formula
        if formula.count('(') != formula.count(')'):
            raise ValidationError("Filter formula has unmatched parentheses")
        
        # Check for dangerous patterns
        for pattern in cls.DANGEROUS_PATTERNS:
            if pattern.search(formula):
                raise ValidationError(f"Filter formula contains potentially dangerous content")
        
        return formula.strip()
    
    @classmethod
    def sanitize_error_message(cls, error: Exception) -> str:
        """Sanitize error messages to prevent information leakage"""
        error_msg = str(error)
        
        # Remove potentially sensitive information
        sanitized = error_msg
        
        # Remove full file paths
        sanitized = re.sub(r'/[^/\s]+/[^/\s]+/[^/\s]+', '[PATH]', sanitized)
        sanitized = re.sub(r'C:\\[^\s]+', '[PATH]', sanitized)
        
        # Remove API keys or tokens
        sanitized = re.sub(r'pat[a-zA-Z0-9]{14}\.[a-zA-Z0-9]{64}', '[API_KEY]', sanitized)
        sanitized = re.sub(r'key[a-zA-Z0-9]{17}', '[API_KEY]', sanitized)
        
        # Remove email addresses
        sanitized = re.sub(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', '[EMAIL]', sanitized)
        
        # Limit error message length
        if len(sanitized) > 500:
            sanitized = sanitized[:497] + "..."
        
        return sanitized

# Decorator for automatic validation
def validate_airtable_ids(func):
    """Decorator to automatically validate Airtable IDs in function arguments"""
    def wrapper(*args, **kwargs):
        # Validate base_id if present
        if 'base_id' in kwargs:
            kwargs['base_id'] = AirtableValidator.validate_base_id(kwargs['base_id'])
        
        # Validate table_id if present
        if 'table_id' in kwargs:
            kwargs['table_id'] = AirtableValidator.validate_table_id(kwargs['table_id'])
        
        # Validate record_id if present
        if 'record_id' in kwargs:
            kwargs['record_id'] = AirtableValidator.validate_record_id(kwargs['record_id'])
        
        # Validate max_records if present
        if 'max_records' in kwargs:
            kwargs['max_records'] = AirtableValidator.validate_max_records(kwargs['max_records'])
        
        # Validate fields if present
        if 'fields' in kwargs:
            kwargs['fields'] = AirtableValidator.validate_fields_dict(kwargs['fields'])
        
        return func(*args, **kwargs)
    
    return wrapper