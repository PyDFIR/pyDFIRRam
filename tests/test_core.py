def test_generic():
    from pydfirram.core.base import Generic, OperatingSystem

    os = OperatingSystem.WINDOWS

    generic = Generic(os)

    assert str(generic) == "Generic OS: WINDOWS"
    generic.get_plugins_list()
