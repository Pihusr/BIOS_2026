import importlib

def load_plugin(module_name: str, function_name: str):
    module = importlib.import_module(module_name)
    loader = getattr(module, function_name)
    return loader()
