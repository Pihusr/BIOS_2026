import yaml
from PIL import Image
from jinja2.filters import do_xmlattr

DEBUG = False

def legacy_load(text: str):
    return yaml.load(text, Loader=yaml.Loader)

def legacy_image(path: str):
    return Image.open(path)

def legacy_render(value: dict):
    return do_xmlattr(value)

if False:
    legacy_load("a: 1")

if DEBUG:
    legacy_image("legacy.png")
