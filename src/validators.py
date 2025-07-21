#!/usr/bin/env python3
"""
Enhanced Input Validation and Sanitization for Airtable MCP Server
================================================================

This module provides comprehensive input validation to prevent:
- Malicious inputs
- Invalid Airtable ID formats
- Data injection attacks
- Formula injection attacks (NEW)
- Type confusion attacks
- Out-of-range values
- Information leakage in errors (ENHANCED)
"""

import re
import logging
import hashlib
from typing import Any, Dict, List, Optional, Union
from datetime import datetime

logger = logging.getLogger(__name__)

class ValidationError(Exception):
    """Custom exception for validation errors"""
    pass

class SecurityError(ValidationError):
    """Custom exception for security-related validation errors"""
    pass

class AirtableValidator:
    """Comprehensive validator for Airtable MCP inputs with enhanced security"""
    
    # Airtable ID patterns
    BASE_ID_PATTERN = re.compile(r'^app[a-zA-Z0-9]{14}$')
    TABLE_ID_PATTERN = re.compile(r'^tbl[a-zA-Z0-9]{14}$')
    RECORD_ID_PATTERN = re.compile(r'^rec[a-zA-Z0-9]{14}$')
    FIELD_ID_PATTERN = re.compile(r'^fld[a-zA-Z0-9]{14}$')
    VIEW_ID_PATTERN = re.compile(r'^viw[a-zA-Z0-9]{14}$')
    
    # Enhanced security limits
    MAX_RECORDS = 1000
    MAX_FIELD_NAME_LENGTH = 200
    MAX_TEXT_FIELD_LENGTH = 100000  # Airtable's limit
    MAX_FILTER_FORMULA_LENGTH = 5000
    MAX_SEARCH_VALUE_LENGTH = 1000  # NEW: Limit search values
    MAX_DATE_RANGE_LENGTH = 50      # NEW: Limit date range strings
    
    # Enhanced dangerous patterns to block
    DANGEROUS_PATTERNS = [
        re.compile(r'<script[^>]*>', re.IGNORECASE),
        re.compile(r'javascript:', re.IGNORECASE),
        re.compile(r'on\w+\s*=', re.IGNORECASE),
        re.compile(r'eval\s*\(', re.IGNORECASE),
        re.compile(r'expression\s*\(', re.IGNORECASE),
        re.compile(r'vbscript:', re.IGNORECASE),
        re.compile(r'data:text/html', re.IGNORECASE),
        re.compile(r'<iframe', re.IGNORECASE),
        re.compile(r'<object', re.IGNORECASE),
        re.compile(r'<embed', re.IGNORECASE),
        re.compile(r'<form', re.IGNORECASE),
        re.compile(r'<input', re.IGNORECASE),
    ]
    
    # NEW: Airtable formula injection patterns
    FORMULA_INJECTION_PATTERNS = [
        re.compile(r';\s*(UPDATE|DELETE|INSERT|DROP|CREATE|ALTER)\s+', re.IGNORECASE),
        re.compile(r'CONCATENATE\s*\(.*javascript:', re.IGNORECASE),
        re.compile(r'HYPERLINK\s*\(\s*["\']javascript:', re.IGNORECASE),
        re.compile(r'SUBSTITUTE\s*\([^)]*<script', re.IGNORECASE),
        re.compile(r'REGEX_REPLACE\s*\([^)]*<script', re.IGNORECASE),
        re.compile(r'IF\s*\([^)]*</?\s*script', re.IGNORECASE),
    ]
    
    # NEW: Field name patterns for safe formula usage
    SAFE_FIELD_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9_\s\-\.]+$')
    
    @classmethod
    def validate_base_id(cls, base_id: Any) -> str:
        """Validate Airtable base ID format with strict type checking"""
        if base_id is None:
            raise ValidationError("Base ID cannot be None")
        
        if not isinstance(base_id, str):
            raise ValidationError(f"Base ID must be a string, got {type(base_id).__name__}: {cls._sanitize_for_error(base_id)}")
        
        if len(base_id) == 0:
            raise ValidationError("Base ID cannot be empty")
        
        if not cls.BASE_ID_PATTERN.match(base_id):
            raise ValidationError(f"Invalid base ID format: {cls._sanitize_for_error(base_id)}. Must be 'app' + 14 alphanumeric characters")
        
        return base_id
    
    @classmethod
    def validate_table_id(cls, table_id: Any) -> str:
        """Validate Airtable table ID format with strict type checking"""
        if table_id is None:
            raise ValidationError("Table ID cannot be None")
        
        if not isinstance(table_id, str):
            raise ValidationError(f"Table ID must be a string, got {type(table_id).__name__}: {cls._sanitize_for_error(table_id)}")
        
        if len(table_id) == 0:
            raise ValidationError("Table ID cannot be empty")
        
        if not cls.TABLE_ID_PATTERN.match(table_id):
            raise ValidationError(f"Invalid table ID format: {cls._sanitize_for_error(table_id)}. Must be 'tbl' + 14 alphanumeric characters")
        
        return table_id
    
    @classmethod
    def validate_record_id(cls, record_id: Any) -> str:
        """Validate Airtable record ID format with strict type checking"""
        if record_id is None:
            raise ValidationError("Record ID cannot be None")
        
        if not isinstance(record_id, str):
            raise ValidationError(f"Record ID must be a string, got {type(record_id).__name__}: {cls._sanitize_for_error(record_id)}")
        
        if len(record_id) == 0:
            raise ValidationError("Record ID cannot be empty")
        
        if not cls.RECORD_ID_PATTERN.match(record_id):
            raise ValidationError(f"Invalid record ID format: {cls._sanitize_for_error(record_id)}. Must be 'rec' + 14 alphanumeric characters")
        
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
                raise ValidationError(f"max_records must be a number, got: {cls._sanitize_for_error(max_records)}")
        
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
        """Validate field name with enhanced security checks"""
        if not isinstance(field_name, str):
            raise ValidationError(f"Field name must be a string, got {type(field_name).__name__}")
        
        if len(field_name) == 0:
            raise ValidationError("Field name cannot be empty")
        
        if len(field_name) > cls.MAX_FIELD_NAME_LENGTH:
            raise ValidationError(f"Field name too long: {len(field_name)} > {cls.MAX_FIELD_NAME_LENGTH}")
        
        # Enhanced security: Check for dangerous patterns
        for pattern in cls.DANGEROUS_PATTERNS:
            if pattern.search(field_name):
                logger.warning(f"Potentially dangerous field name detected: {cls._hash_sensitive_data(field_name)}")
                raise SecurityError("Field name contains potentially dangerous content")
        
        return field_name.strip()
    
    @classmethod
    def validate_field_name_for_formula(cls, field_name: str) -> str:
        """NEW: Validate field name specifically for safe use in Airtable formulas"""
        if not isinstance(field_name, str):
            raise ValidationError(f"Field name must be a string, got {type(field_name).__name__}")
        
        field_name = field_name.strip()
        
        if len(field_name) == 0:
            raise ValidationError("Field name cannot be empty")
        
        if len(field_name) > cls.MAX_FIELD_NAME_LENGTH:
            raise ValidationError(f"Field name too long: {len(field_name)} > {cls.MAX_FIELD_NAME_LENGTH}")
        
        # Check for safe field name characters only
        if not cls.SAFE_FIELD_NAME_PATTERN.match(field_name):
            logger.warning(f"Unsafe field name for formula: {cls._hash_sensitive_data(field_name)}")
            raise SecurityError(f"Field name contains invalid characters for formula use. Only alphanumeric, spaces, hyphens, underscores, and dots allowed.")
        
        # Check for formula injection patterns
        for pattern in cls.FORMULA_INJECTION_PATTERNS:
            if pattern.search(field_name):
                logger.warning(f"Formula injection attempt detected in field name: {cls._hash_sensitive_data(field_name)}")
                raise SecurityError("Field name contains potentially dangerous formula content")
        
        # Check general dangerous patterns
        for pattern in cls.DANGEROUS_PATTERNS:
            if pattern.search(field_name):
                logger.warning(f"Dangerous pattern detected in field name: {cls._hash_sensitive_data(field_name)}")
                raise SecurityError("Field name contains potentially dangerous content")
        
        return field_name
    
    @classmethod
    def validate_search_value(cls, search_value: str) -> str:
        """NEW: Validate search values with comprehensive security checks"""
        if not isinstance(search_value, str):
            raise ValidationError(f"Search value must be a string, got {type(search_value).__name__}")
        
        if len(search_value) > cls.MAX_SEARCH_VALUE_LENGTH:
            raise ValidationError(f"Search value too long: {len(search_value)} > {cls.MAX_SEARCH_VALUE_LENGTH}")
        
        # Check for dangerous patterns
        for pattern in cls.DANGEROUS_PATTERNS:
            if pattern.search(search_value):
                logger.warning(f"Potentially dangerous search value detected: {cls._hash_sensitive_data(search_value)}")
                raise SecurityError("Search value contains potentially dangerous content")
        
        # Check for formula injection patterns
        for pattern in cls.FORMULA_INJECTION_PATTERNS:
            if pattern.search(search_value):
                logger.warning(f"Formula injection attempt in search value: {cls._hash_sensitive_data(search_value)}")
                raise SecurityError("Search value contains potentially dangerous formula content")
        
        return search_value.strip()
    
    @classmethod
    def validate_date_range(cls, date_range: str) -> str:
        """NEW: Validate date range strings"""
        if not isinstance(date_range, str):
            raise ValidationError(f"Date range must be a string, got {type(date_range).__name__}")
        
        if len(date_range) > cls.MAX_DATE_RANGE_LENGTH:
            raise ValidationError(f"Date range string too long: {len(date_range)} > {cls.MAX_DATE_RANGE_LENGTH}")
        
        # Check for dangerous patterns
        for pattern in cls.DANGEROUS_PATTERNS:
            if pattern.search(date_range):
                logger.warning(f"Potentially dangerous date range detected: {cls._hash_sensitive_data(date_range)}")
                raise SecurityError("Date range contains potentially dangerous content")
        
        return date_range.strip()
    
    @classmethod
    def validate_field_value(cls, field_name: str, value: Any) -> Any:
        """Validate and sanitize field value with enhanced security"""
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
        """Validate text field value with enhanced security"""
        if len(value) > cls.MAX_TEXT_FIELD_LENGTH:
            raise ValidationError(f"Text field '{field_name}' too long: {len(value)} > {cls.MAX_TEXT_FIELD_LENGTH}")
        
        # Check for dangerous patterns
        for pattern in cls.DANGEROUS_PATTERNS:
            if pattern.search(value):
                logger.warning(f"Potentially dangerous content detected in field '{field_name}': {cls._hash_sensitive_data(value[:100])}")
                # Sanitize instead of rejecting for better user experience
                value = pattern.sub('[SANITIZED]', value)
        
        # Check for formula injection patterns
        for pattern in cls.FORMULA_INJECTION_PATTERNS:
            if pattern.search(value):
                logger.warning(f"Formula injection attempt detected in field '{field_name}': {cls._hash_sensitive_data(value[:100])}")
                value = pattern.sub('[SANITIZED]', value)
        
        return value
    
    @classmethod
    def _validate_numeric_value(cls, field_name: str, value: Union[int, float]) -> Union[int, float]:
        """Validate numeric field value"""
        # Check for reasonable numeric limits
        if abs(value) > 1e15:  # Very large numbers
            raise ValidationError(f"Numeric value for '{field_name}' too large: {value}")
        
        # Check for NaN and infinity
        if isinstance(value, float):
            if value != value:  # NaN check
                raise ValidationError(f"Numeric value for '{field_name}' is NaN")
            if value == float('inf') or value == float('-inf'):
                raise ValidationError(f"Numeric value for '{field_name}' is infinite")
        
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
        """Validate Airtable filter formula with enhanced security"""
        if formula is None:
            return None
        
        if not isinstance(formula, str):
            raise ValidationError(f"Filter formula must be a string, got {type(formula).__name__}")
        
        if len(formula) > cls.MAX_FILTER_FORMULA_LENGTH:
            raise ValidationError(f"Filter formula too long: {len(formula)} > {cls.MAX_FILTER_FORMULA_LENGTH}")
        
        # Basic sanity checks for formula
        if formula.count('(') != formula.count(')'):
            raise ValidationError("Filter formula has unmatched parentheses")
        
        if formula.count('{') != formula.count('}'):
            raise ValidationError("Filter formula has unmatched braces")
        
        # Check for dangerous patterns
        for pattern in cls.DANGEROUS_PATTERNS:
            if pattern.search(formula):
                logger.warning(f"Dangerous pattern detected in formula: {cls._hash_sensitive_data(formula[:100])}")
                raise SecurityError("Filter formula contains potentially dangerous content")
        
        # Check for formula injection patterns
        for pattern in cls.FORMULA_INJECTION_PATTERNS:
            if pattern.search(formula):
                logger.warning(f"Formula injection attempt detected: {cls._hash_sensitive_data(formula[:100])}")
                raise SecurityError("Filter formula contains potentially dangerous formula content")
        
        return formula.strip()
    
    @classmethod
    def sanitize_error_message(cls, error: Exception) -> str:
        """Enhanced error message sanitization to prevent information leakage"""
        error_msg = str(error)
        
        # Remove potentially sensitive information
        sanitized = error_msg
        
        # Remove full file paths
        sanitized = re.sub(r'/[^/\s]+/[^/\s]+/[^/\s]+', '[PATH]', sanitized)
        sanitized = re.sub(r'C:\\[^\s]+', '[PATH]', sanitized)
        sanitized = re.sub(r'/home/[^/\s]+', '[HOME]', sanitized)
        sanitized = re.sub(r'/usr/[^/\s]+', '[USR]', sanitized)
        
        # Remove API keys or tokens (enhanced patterns)
        sanitized = re.sub(r'pat[a-zA-Z0-9]{14}\.[a-zA-Z0-9]{64}', '[API_KEY]', sanitized)
        sanitized = re.sub(r'key[a-zA-Z0-9]{17}', '[API_KEY]', sanitized)
        sanitized = re.sub(r'sk-[a-zA-Z0-9]{48}', '[API_KEY]', sanitized)
        sanitized = re.sub(r'xoxb-[0-9]+-[0-9]+-[0-9]+-[a-zA-Z0-9]{24}', '[API_KEY]', sanitized)
        
        # Remove email addresses
        sanitized = re.sub(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', '[EMAIL]', sanitized)
        
        # Remove IP addresses
        sanitized = re.sub(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', '[IP]', sanitized)
        
        # Remove potential usernames in paths
        sanitized = re.sub(r'/Users/[^/\s]+', '[USER]', sanitized)
        
        # Remove database connection strings
        sanitized = re.sub(r'postgres://[^@]+@[^/\s]+', 'postgres://[CREDENTIALS]@[HOST]', sanitized)
        sanitized = re.sub(r'mysql://[^@]+@[^/\s]+', 'mysql://[CREDENTIALS]@[HOST]', sanitized)
        
        # Limit error message length
        if len(sanitized) > 500:
            sanitized = sanitized[:497] + "..."
        
        return sanitized
    
    @classmethod
    def sanitize_for_logging(cls, data: Any) -> str:
        """NEW: Sanitize data for secure logging"""
        sensitive_fields = {
            'password', 'token', 'key', 'secret', 'api_key', 
            'auth', 'credential', 'session', 'cookie', 'jwt',
            'authorization', 'bearer', 'oauth'
        }
        
        if isinstance(data, dict):
            sanitized = {}
            for key, value in data.items():
                if any(sensitive in key.lower() for sensitive in sensitive_fields):
                    sanitized[key] = '[REDACTED]'
                elif isinstance(value, str) and len(value) > 200:
                    sanitized[key] = value[:200] + '...[TRUNCATED]'
                else:
                    sanitized[key] = value
            return str(sanitized)
        elif isinstance(data, str):
            # Check if the string looks like sensitive data
            for sensitive in sensitive_fields:
                if sensitive in data.lower():
                    return '[POTENTIALLY_SENSITIVE_DATA]'
            return data[:200] + '...[TRUNCATED]' if len(data) > 200 else data
        
        return str(data)
    
    @classmethod
    def _sanitize_for_error(cls, data: Any) -> str:
        """NEW: Sanitize data for inclusion in error messages"""
        if isinstance(data, str):
            if len(data) > 50:
                return data[:47] + "..."
        return str(data)[:50]
    
    @classmethod
    def _hash_sensitive_data(cls, data: str) -> str:
        """NEW: Create hash of sensitive data for logging without exposure"""
        return hashlib.sha256(data.encode()).hexdigest()[:16]

# Enhanced decorator for automatic validation
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

# NEW: Additional security utilities
class SecurityUtils:
    """Additional security utilities for the MCP server"""
    
    @staticmethod
    def generate_secure_session_id() -> str:
        """Generate a cryptographically secure session ID"""
        import secrets
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def is_safe_filename(filename: str) -> bool:
        """Check if a filename is safe for use"""
        if not filename or filename in ('.', '..'):
            return False
        
        # Check for path traversal
        if '/' in filename or '\\' in filename:
            return False
        
        # Check for dangerous extensions
        dangerous_extensions = {'.exe', '.bat', '.sh', '.ps1', '.cmd', '.scr'}
        if any(filename.lower().endswith(ext) for ext in dangerous_extensions):
            return False
        
        return True
    
    @staticmethod
    def validate_url_safe(url: str) -> bool:
        """Basic URL validation for safety"""
        if not url:
            return False
        
        # Must start with http or https
        if not url.lower().startswith(('http://', 'https://')):
            return False
        
        # Check for dangerous protocols
        dangerous_protocols = ['javascript:', 'data:', 'vbscript:', 'file:']
        if any(protocol in url.lower() for protocol in dangerous_protocols):
            return False
        
        return True
