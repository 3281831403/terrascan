package accurics

mediumSeverityViolation[retVal] {
    resource := input.severity_test_resource[_]
    resource.config.violate == true
    retVal := {"Id": resource.id}
}
