from cyberbattle.simulation import model as m
from cyberbattle.simulation.model import NodeID, NodeInfo, VulnerabilityID, VulnerabilityInfo
from typing import Dict, Iterator, cast, Tuple

default_allow_rules = [
    m.FirewallRule("SSH", m.RulePermission.ALLOW),
]

nodes = {
    "NodeA": m.NodeInfo(
        services=[m.ListeningService("HTTPS")],
        value=50,
        properties=[],
        vulnerabilities=dict(
            NavigateWebDirectoryFurther=m.VulnerabilityInfo(
                description="for validate_environment",
                type=m.VulnerabilityType.REMOTE,
                outcome=m.LeakedCredentials(credentials=[m.CachedCredential(node="na",port="na",credential="na")]),
                cost=1.0
            ),
        )),
    "NodeB": m.NodeInfo(
        services=[m.ListeningService("HTTPS")],
        value=50,
        properties=[],
        vulnerabilities=dict(
            NavigateWebDirectoryFurther=m.VulnerabilityInfo(
                description="for validate_environment",
                type=m.VulnerabilityType.REMOTE,
                outcome=m.ExploitFailed(),
                cost=1.0
            ),
        )),
    'foothold': m.NodeInfo(
        services=[],
        properties=[""],
        value=0,
        vulnerabilities=dict(
            VulnA=m.VulnerabilityInfo(
                description="leak node A",
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedNodesId(["NodeA"]),
                cost=1.0
            ),
            VulnB=m.VulnerabilityInfo(
                description="leak node B",
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedNodesId(["NodeB"]),
                cost=1.0
            )),
        agent_installed=True,
        reimagable=False),
}

global_vulnerability_library: Dict[VulnerabilityID, VulnerabilityInfo] = dict([])

ENV_IDENTIFIERS = m.infer_constants_from_nodes(
    cast(Iterator[Tuple[NodeID, NodeInfo]], list(nodes.items())),
    global_vulnerability_library)


def new_environment() -> m.Environment:
    return m.Environment(
        network=m.create_network(nodes),
        vulnerability_library=global_vulnerability_library,
        identifiers=ENV_IDENTIFIERS
    )
