from cyberbattle.simulation import model as m
from cyberbattle.simulation.model import NodeID, NodeInfo, VulnerabilityID, VulnerabilityInfo
from typing import Dict, Iterator, cast, Tuple

default_allow_rules = [
    m.FirewallRule("SSH", m.RulePermission.ALLOW),
]

nodes = {
    "workstation": m.NodeInfo(
        services=[m.ListeningService("SSH")],
        firewall=m.FirewallConfiguration(incoming=default_allow_rules,
                                         outgoing=default_allow_rules),
        value=100,
        properties=["placeholder"],
        owned_string="Node owned via AdminEscalation",
        vulnerabilities=dict(
            AdminEscalationVulnerability=m.VulnerabilityInfo(
                description="arbitrary vulnerability that escalates to admin remotely",
                type=m.VulnerabilityType.REMOTE,
                outcome=m.AdminEscalation(),
                reward_string="workstation admin privilege gained",
                cost=1.0
            ),
        )
    ),
    'foothold': m.NodeInfo(
        services=[],
        value=0,
        vulnerabilities=dict(
            RevealWorkstationAndDummyCredential=m.VulnerabilityInfo(
                description="reveal workstation",
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedCredentials(credentials=[m.CachedCredential(node="workstation", port="SSH", credential="dummy_cred")]),
                reward_string="workstation revealed",
                cost=1.0
            )),
        agent_installed=True,
        reimagable=False),
}

global_vulnerability_library: Dict[VulnerabilityID, VulnerabilityInfo] = dict([])

# Environment constants
ENV_IDENTIFIERS = m.infer_constants_from_nodes(
    cast(Iterator[Tuple[NodeID, NodeInfo]], list(nodes.items())),
    global_vulnerability_library)


def new_environment() -> m.Environment:
    return m.Environment(
        network=m.create_network(nodes),
        vulnerability_library=global_vulnerability_library,
        identifiers=ENV_IDENTIFIERS
    )
