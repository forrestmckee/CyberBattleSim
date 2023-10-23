# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from ..samples.internal_id_error import internal_id_error
from . import cyberbattle_env


class CyberBattleInternalIDError(cyberbattle_env.CyberBattleEnv):

    def __init__(self, **kwargs):
        super().__init__(
            initial_environment=internal_id_error.new_environment(),
            **kwargs)
