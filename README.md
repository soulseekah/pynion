This is a low-level set of primitives to allow interaction with the Tor network for research and experimental purposes.
This implementation should not be used as a replacement for the official implementation.
Support is aimed for version 3 of the protocol specification.

```python
import directory, circuit, cell, random

authority = directory.Authority()
consensus = authority.get_consensus()

routers = filter( circuit.Circuit.is_good_exit, consensus.routers )

c = circuit.Circuit()
c.add( random.choice( routers ) )
c.add( random.choice( routers ) )
c.add( random.choice( routers ) )

c.build()
```
