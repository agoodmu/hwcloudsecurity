from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


class UnLimitedIngressTraffic(BaseResourceCheck):
    def __init__(self, check_id, port,ipaddress=None):
        name = "Ensure no security groups allow ingress from %s to port %d" % (ipaddress,port)
        supported_resources = ['huaweicloud_networking_secgroup_rule']
        categories = [CheckCategories.NETWORKING]
        super().__init__(name=name, id=check_id, categories=categories, supported_resources=supported_resources)
        self.port = port
        self.ipaddress = ipaddress

    def scan_resource_conf(self, conf: dict[str,list[any]]) -> CheckResult:
        """
            Looks for configuration at security group ingress rules :
            https://registry.terraform.io/providers/huaweicloud/huaweicloud/latest/docs/resources/networking_secgroup_rule

            Return PASS if:
            - The resource is an huaweicloud_networking_secgroup_rule 'ingress' that does not violate the check.
            - The resource is not an huaweicloud_networking_secgroup_rule
            - The resource is an huaweicloud_networking_secgroup_rule of type "Egress"

            Return FAIL if:
            - The resource is an huaweicloud_networking_secgroup_rule of type 'ingress' that violates the check.

        :param conf: huaweicloud_networking_secgroup_rule configuration
        :return: <CheckResult>
        """

        if conf['direction'][0] == 'ingress':  # This means it's an huaweicloud_networking_secgroup_rule egress resource.
            return CheckResult.PASSED
        
        """
        check if the remote ip address is allowed
        """
        if self.ipaddress != None:
            if type(self.ipaddress) is list:
                if 'remote_ip_prefix' in conf:
                    if conf['remote_ip_prefix'] in self.ipaddress:
                        return CheckResult.FAILED
            else:
                if 'remote_ip_prefix' in conf:
                    if conf['remote_ip_prefix'] == self.ipaddress:
                        return CheckResult.FAILED

        """
        check if port is allowed
        """
        if 'port_range_min' in conf:
            if int(conf['port_range_min']) <= int(self.port) <= int(conf['port_range_max']):
                return CheckResult.FAILED
            
        if 'ports' in conf:
            if str(self.port) in str.split(conf['ports'],","):
                return CheckResult.FAILED
        
        return CheckResult.PASSED
    

class SecurityGroupUnrestrictedIngress22(UnLimitedIngressTraffic):
    def __init__(self):
        super().__init__(check_id="HW_NETWORK_001", port=22)
    

check = SecurityGroupUnrestrictedIngress22()