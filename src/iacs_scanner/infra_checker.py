


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



