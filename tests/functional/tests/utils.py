"""Helper functions."""

import logging

import tenacity
from zaza import model


@tenacity.retry(
    stop=tenacity.stop_after_attempt(3),
    wait=tenacity.wait_exponential(multiplier=1, min=2, max=10),
)
def strict_run_on_unit(*arg, **kwargs):
    """Stricted version of `zaza.model.run_on_unit`."""
    result = model.run_on_unit(*arg, **kwargs)
    return _check_result(result)


def _check_result(result):
    """Check if `zaza.model.run_on_unit` completed without error."""
    if not result:
        raise Exception("Failed to get a result from run_on_unit command.")
    if result["Code"] != "0":
        logging.error(
            "Failed on excecuting command on unit. Result code: {}".format(result["Code"])
        )
        logging.error("Returned: \n{}".format(result))
        raise Exception("Command returned non-zero return code.")
    return result
