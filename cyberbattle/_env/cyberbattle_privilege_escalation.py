from ..samples.privilege_escalation import privilege_escalation_example
from . import cyberbattle_env


class CyberBattlePrivilegeEscalation(cyberbattle_env.CyberBattleEnv):
    """CyberBattle simulation showing potential privilege escalation bug"""

    def __init__(self, **kwargs):
        super().__init__(
            initial_environment=privilege_escalation_example.new_environment(),
            **kwargs)
