from infra_checker import IR, IaCChecker


def run_infra_checks(files_with_types):  # [(path, type)]
    checker = IaCChecker()
    for filepath, iac_type in files_with_types:
        intermediate_representation = IR.construct(filepath, iac_type)
        checker.run_checks(intermediate_representation)