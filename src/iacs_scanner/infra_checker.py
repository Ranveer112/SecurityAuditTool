


PARSER_REGISTRY = {
    'terraform': parse_terraform,
}

#TODO -
# 1) Learn terraform(https://developer.hashicorp.com/terraform/tutorials/aws-get-started/aws-create)
# 2) Add static checks scanning for terraform files, and then later experiment with LLM based scanning.
# 3) Using terraform apply for generate a JSON IR from the .tf files.
# 4) Scanning limited to no data blocks in .tf files.
# 5) Problems:
# a) Remote state access
# b) Running terraform init
# c) credentials for cloud providers.


#Change of plans
#Experiment with an LLM based scanning using LangChain
#Data source would be AWS docs, security standards, best practices, tfcheck security yaml etc.
#RAG would be used to fetch relevant rules, practices for a given IaC file 
#and chain of that + system prompting + IaC file content to generaty security vulnerabilities

#Do I solve any problem with this?
#As soon as any of the data source is updated, the LLM might pick it


#Downsides with this approach
#1) LLM's hallucinate, while static checks do not(system prompt can enforce citations)
#2) LLM's are expensive
#3) RAG might find contradictory info in the data source



#Learning Langchain
#https://python.langchain.com/docs/get_started/introduction
#https://python.langchain.com/docs/get_started/quickstart

class IaCChecker:
    def __init__(self):
        self.checks = [check_open_ports, check_missing_tags, ...]

    def run_checks(self, ir):
        for res in ir.resources:
            for check in self.checks:
                msg = check(res)
                if msg:
                    print(msg)

class IR:
    def __init__(self, resources):
        self.resources = resources  # list[IaCResource]

    @staticmethod
    def construct(path, iac_type):
        parser = PARSER_REGISTRY.get(iac_type)
        resources = parser(path)
        return IR(resources)


class IaCResource:
    def __init__(self, id, type, name, props, depends_on):
        self.id = id
        self.type = type
        self.name = name
        self.props = props
        self.depends_on = depends_on



