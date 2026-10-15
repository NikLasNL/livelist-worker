"""
worker/executor.py — выполнение задач из модулей.
"""

import inspect


class TaskExecutor:
    def __init__(self, loader):
        self.loader = loader

    async def run(self, task_name, params):
        if ":" in task_name:
            module_name, func_name = task_name.split(":", 1)
        else:
            module_name, func_name = task_name, "run"

        mod = self.loader.get(module_name)
        if mod is None:
            mod = self.loader.load_module(module_name)

        func = getattr(mod, func_name, None)
        if func is None:
            raise RuntimeError(f"Func {func_name} not in {module_name}")

        if inspect.iscoroutinefunction(func):
            return await func(**params)
        return func(**params)