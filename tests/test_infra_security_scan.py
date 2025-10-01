import pytest
from tests.utils import DummyLogger
from unittest.mock import patch, MagicMock, mock_open
import json
import tempfile
import os


def test_infra_security_scan_imports():
    """Test 1: Verify that the module compiles and can be imported successfully."""
    try:
        from iacs_scanner import infra_security_scan
        assert hasattr(infra_security_scan, 'find_terraform_vulnerabilities')
        assert hasattr(infra_security_scan, 'output_to_file')
    except ImportError as e:
        pytest.fail(f"Failed to import infra_security_scan module: {e}")
    except SyntaxError as e:
        pytest.fail(f"Syntax error in infra_security_scan module: {e}")


def test_find_terraform_vulnerabilities_with_mocked_agent():
    """Test 2: Verify find_terraform_vulnerabilities returns output when agent is mocked."""
    from iacs_scanner.infra_security_scan import find_terraform_vulnerabilities
    
    logger = DummyLogger()
    iac_content = """
    resource "aws_s3_bucket" "example" {
        bucket = "my-bucket"
    }
    """
    
    # Mock the expected response from the LLM
    mock_response = {
        "vulnerabilities": [
            {
                "vulnerability": "Ensure S3 bucket has encryption enabled",
                "code_block": [
                    {"line_number": 2, "code": 'resource "aws_s3_bucket" "example" {'},
                    {"line_number": 3, "code": '    bucket = "my-bucket"'},
                    {"line_number": 4, "code": '}'}
                ],
                "remediation": "Add server-side encryption configuration to the S3 bucket",
                "justification": "S3 buckets should have encryption enabled to protect data at rest"
            }
        ]
    }
    
    # Mock the ChatGroq LLM and the chain execution
    with patch('iacs_scanner.infra_security_scan.ChatGroq') as mock_chatgroq, \
         patch('iacs_scanner.infra_security_scan.os.getenv') as mock_getenv:
        
        # Setup environment variable mocks
        mock_getenv.side_effect = lambda key: {
            'GROQ_MODEL_NAME': 'llama-3.1-70b-versatile',
            'GROQ_TEMPERATURE': '0.0',
            'GROQ_API_KEY': 'test-api-key'
        }.get(key)
        
        # Create a mock LLM instance
        mock_llm_instance = MagicMock()
        mock_chatgroq.return_value = mock_llm_instance
        
        # Mock the chain's invoke method to return our mock response
        with patch('iacs_scanner.infra_security_scan.ChatPromptTemplate') as mock_prompt, \
             patch('iacs_scanner.infra_security_scan.JsonOutputParser') as mock_parser:
            
            # Setup the chain mock
            mock_prompt_instance = MagicMock()
            mock_parser_instance = MagicMock()
            mock_prompt.from_messages.return_value = mock_prompt_instance
            mock_parser.return_value = mock_parser_instance
            
            # Mock the chain (prompt | llm | parser)
            mock_chain = MagicMock()
            mock_chain.invoke.return_value = mock_response
            
            # Override the __or__ operator to return our mock chain
            mock_prompt_instance.__or__ = MagicMock(return_value=MagicMock(__or__=MagicMock(return_value=mock_chain)))
            
            result = find_terraform_vulnerabilities(iac_content, logger)
            
            # Assertions
            assert result is not None
            assert 'vulnerabilities' in result
            assert len(result['vulnerabilities']) == 1
            assert result['vulnerabilities'][0]['vulnerability'] == "Ensure S3 bucket has encryption enabled"
            assert len(logger.error_messages) == 0


def test_find_terraform_vulnerabilities_llm_initialization_error():
    """Test that find_terraform_vulnerabilities handles LLM initialization errors gracefully."""
    from iacs_scanner.infra_security_scan import find_terraform_vulnerabilities
    
    logger = DummyLogger()
    iac_content = "resource 'aws_s3_bucket' 'example' {}"
    
    # Mock ChatGroq to raise an exception
    with patch('iacs_scanner.infra_security_scan.ChatGroq') as mock_chatgroq:
        mock_chatgroq.side_effect = Exception("API key invalid")
        
        result = find_terraform_vulnerabilities(iac_content, logger)
        
        # Assertions
        assert result is None
        assert len(logger.error_messages) == 1
        assert "An error occured while initializing the LLM" in logger.error_messages[0][0]


def test_output_to_file_json_format():
    """Test 3a: Verify output_to_file writes successfully to a file in JSON format."""
    from iacs_scanner.infra_security_scan import output_to_file
    
    test_result = {
        "vulnerabilities": [
            {
                "vulnerability": "Ensure S3 bucket has encryption enabled",
                "code_block": [
                    {"line_number": 2, "code": 'resource "aws_s3_bucket" "example" {'},
                    {"line_number": 3, "code": '    bucket = "my-bucket"'}
                ],
                "remediation": "Add server-side encryption configuration",
                "justification": "S3 buckets should have encryption enabled"
            }
        ]
    }
    
    # Create a temporary file
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as temp_file:
        temp_filename = temp_file.name
    
    try:
        # Call output_to_file with json_output=True
        output_to_file(test_result, temp_filename, json_output=True)
        
        # Verify the file was written correctly
        assert os.path.exists(temp_filename)
        
        with open(temp_filename, 'r', encoding='utf-8') as f:
            written_data = json.load(f)
        
        assert written_data == test_result
        assert 'vulnerabilities' in written_data
        assert len(written_data['vulnerabilities']) == 1
        
    finally:
        # Clean up the temporary file
        if os.path.exists(temp_filename):
            os.remove(temp_filename)


def test_output_to_file_text_format():
    """Test 3b: Verify output_to_file writes successfully to a file in text format."""
    from iacs_scanner.infra_security_scan import output_to_file
    
    test_result = {
        "vulnerabilities": [
            {
                "vulnerability": "Ensure S3 bucket has encryption enabled",
                "code_block": [
                    {"line_number": 2, "code": 'resource "aws_s3_bucket" "example" {'},
                    {"line_number": 3, "code": '    bucket = "my-bucket"'}
                ],
                "remediation": "Add server-side encryption configuration",
                "justification": "S3 buckets should have encryption enabled"
            },
            {
                "vulnerability": "Ensure S3 bucket has versioning enabled",
                "code_block": [
                    {"line_number": 2, "code": 'resource "aws_s3_bucket" "example" {'}
                ],
                "remediation": "Enable versioning on the S3 bucket",
                "justification": "Versioning helps protect against accidental deletion"
            }
        ]
    }
    
    # Create a temporary file
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as temp_file:
        temp_filename = temp_file.name
    
    try:
        # Call output_to_file with json_output=False (default)
        output_to_file(test_result, temp_filename, json_output=False)
        
        # Verify the file was written correctly
        assert os.path.exists(temp_filename)
        
        with open(temp_filename, 'r', encoding='utf-8') as f:
            written_content = f.read()
        
        # Verify content contains expected elements
        assert "Ensure S3 bucket has encryption enabled" in written_content
        assert "Ensure S3 bucket has versioning enabled" in written_content
        assert 'resource "aws_s3_bucket" "example" {' in written_content
        assert "Add server-side encryption configuration" in written_content
        assert "Enable versioning on the S3 bucket" in written_content
        assert "S3 buckets should have encryption enabled" in written_content
        
    finally:
        # Clean up the temporary file
        if os.path.exists(temp_filename):
            os.remove(temp_filename)


def test_output_to_file_empty_vulnerabilities():
    """Test output_to_file handles empty vulnerabilities list."""
    from iacs_scanner.infra_security_scan import output_to_file
    
    test_result = {
        "vulnerabilities": []
    }
    
    # Create a temporary file
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as temp_file:
        temp_filename = temp_file.name
    
    try:
        # Call output_to_file with empty vulnerabilities
        output_to_file(test_result, temp_filename, json_output=False)
        
        # Verify the file exists and is empty or minimal
        assert os.path.exists(temp_filename)
        
        with open(temp_filename, 'r', encoding='utf-8') as f:
            written_content = f.read()
        
        # Should be empty since there are no vulnerabilities
        assert written_content == ""
        
    finally:
        # Clean up the temporary file
        if os.path.exists(temp_filename):
            os.remove(temp_filename)
