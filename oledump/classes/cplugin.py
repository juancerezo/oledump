from abc import abstractmethod
from typing import Iterable, Any
from pathlib import Path

class cPluginMetaclass(type):
    __plugins: list[type["cPluginParent"]] = []
    __decoders: list[type["cDecoderParent"]] = []

    def __init__(cls, name, bases, clsdict):
        if bases and len(bases) > 1:
            raise TypeError(
                f"You cannot declare multiple inheritance of a class that defines abstract methods. Please check implementation of {name}"
            )

        if bases:
            base: type = bases[0]
            for method_name, _ in vars(base).items():
                subclass_method = getattr(cls, method_name)
                if getattr(subclass_method, "__isabstractmethod__", False):
                    raise TypeError(
                        f"Can't create new class {name} with no abstract classmethod {method_name} redefined in the metaclass"
                    )

            if base is cDecoderParent:
                cls.__decoders.append(cls)  # type: ignore

            if base is cPluginParent:
                cls.__plugins.append(cls)  # type: ignore

        return super(cPluginMetaclass, cls).__init__(name, bases, clsdict)
    
    def __repr__(self) -> str:
        return self.__name__

    @classmethod
    def plugins(cls):
        return cls.__plugins

    @classmethod
    def decoders(cls):
        return cls.__decoders


class cDecoderParent(metaclass=cPluginMetaclass):
    @abstractmethod
    def available(self) -> bool:
        pass

    @abstractmethod
    def decode(self) -> bytes:
        pass


class cPluginParent(metaclass=cPluginMetaclass):
    macroOnly: bool = False
    indexQuiet: bool = False
    ran: bool
    ole: Path | None
    data: bytes
    options: str

    def __init__(self, *, filename: Path | None, data: bytes, options: str):
        self.ole = filename
        self.data = data
        self.options = options
        self.ran = False
        pass

    def __repr__(self):
        return f"{self.__class__.__name__}"
    
    @abstractmethod
    def analize(self) -> Iterable[Any]:
        pass


class cPluginParentOle(metaclass=cPluginMetaclass):
    macroOnly = False
    indexQuiet = False
    ran: bool
    ole: Path | None
    data: bytes
    options: str


    def __init__(self, filename: Path | None, data: bytes, options: str):
        self.ole = filename
        self.data = data
        self.options = options
        self.ran = False

    def __repr__(self):
        return f"{self.__class__.__name__}"
    
    @abstractmethod
    def pre_process(self) -> None:
        pass

    @abstractmethod
    def process(self, name: str, stream: bytes) -> None:
        pass

    @abstractmethod
    def post_process(self) -> None:
        pass
