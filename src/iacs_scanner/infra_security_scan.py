from langchain_groq import ChatGroq
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser
import json
import argparse
import os
from utils.context_logger import ContextLoggerAdapter
import logging

from dotenv import load_dotenv
load_dotenv()

def find_terraform_vulnerabilities(iac_content: str, logger: logging.Logger) -> dict|None:
    try:
        llm = ChatGroq(
            model_name=os.getenv("GROQ_MODEL_NAME"),
            temperature=os.getenv("GROQ_TEMPERATURE"),
            api_key=os.getenv("GROQ_API_KEY")
        )
    except Exception as e:
        logger.error("An error occured while initializing the LLM: " + str(e))
        return None

    try:
        parser = JsonOutputParser(pydantic_object={
            "type": "object",
            "properties": {
                "vulnerabilities": {"type": "array", "items": {"type": "object"}},
            }
        }
    )
    except Exception as e:
        logger.error("An error occurred while defining the expected JSON structure: " + str(e))
        return None

    try:       
        prompt = ChatPromptTemplate.from_messages([
        ("system", """For the IAC code below, analyze and list all security vulnerabilities. For each vulnerability, provide:
        1. The vulnerability name should be a security best practice rule in the form of prescriptive guidance (e.g., Ensure X, Require Y, Disable Z). 
        2. The code context (multiple lines of surrounding code)
        3. Recommended remediation
        4. Justification for the finding

        Respond with a JSON object in this format:
        {{
            "vulnerabilities": [
                {{
                    "vulnerability": "name_of_vulnerability.",
                    "code_block": [
                        {{"line_number": 123, "code": "actual_code_line"}},
                        {{"line_number": 124, "code": "next_line_of_code"}}
                    ],
                    "remediation": "how_to_fix_it.",
                    "justification": "why_its_a_problem."
                }}
            ]
        }}
        
        Be specific and include the actual code context where each vulnerability appears.
        """),
        ("user", "IAC Code:\n{input}")
    ])

        
    except Exception as e:
        logger.error("An error occurred while creating the prompt: " + str(e))
        return None

    try:
        chain = prompt | llm | parser
    except Exception as e:
        logger.error("An error occurred while creating the chain: " + str(e))
        return None

    try:
        result = chain.invoke({"input": iac_content})
    except Exception as e:
        logger.error("An error occurred while invoking the chain: " + str(e))
        return None
    return result

def output_to_file(result: dict, output_file: str, json_output: bool = False):
    with open(output_file, "w", newline=None, encoding="utf-8", closefd=True, opener=None) as output_file:
        if json_output:
            json.dump(result, output_file)
        else:
            for vulnerability in result["vulnerabilities"]:
                output_file.write(vulnerability["vulnerability"])
                output_file.write("\n")
                code_block = vulnerability["code_block"]
                for line in code_block:
                    output_file.write(line["code"])
                    output_file.write("\n")
                output_file.write("\n")
                output_file.write(vulnerability["remediation"])
                output_file.write("\n")
                output_file.write(vulnerability["justification"])
                output_file.write("\n")
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("input_file")
    parser.add_argument("output_file")
    log_level_name_to_level = logging.getLevelNamesMapping()
    log_level_names = list(log_level_name_to_level.keys())
    #parser.add_argument("--output-log", type=str, help="Path to the log file", required=False)
    parser.add_argument("--log-level", type=str, choices = log_level_names, help="Logging level. Everything above or equal to the level will be logged", required=False)
    parser.add_argument("--infra-file-type", type=str, choices=["terraform"], help="Infra as code file type. For example - terraform", required=True)
    parser.add_argument("--json-output", action="store_true", help="Output results in JSON format")
    args = parser.parse_args()
    if args.log_level:
        log_level = log_level_name_to_level[args.log_level]
        logger = ContextLoggerAdapter.get_logger(name='infra_scan', log_level=log_level)
    else:
        logger = ContextLoggerAdapter.get_logger(name='infra_scan')
    try:
        with open(args.input_file, "r", newline=None, encoding="utf-8", closefd=True, opener=None) as input_file:
            iac_content = input_file.read()
            if args.json_output:
                output_to_file(find_terraform_vulnerabilities(iac_content, logger), args.output_file, json_output=True)
            else:
                output_to_file(find_terraform_vulnerabilities(iac_content, logger), args.output_file)
    except FileNotFoundError:
        logger.error("File not found")
    except Exception as e:
        logger.error("An error occurred while running the scanner: " + str(e))


