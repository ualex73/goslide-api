
# GoSlide Open Cloud API

Python API to utilise the GoSlide Open Cloud and Local JSON API

## Requirements

- Python >= 3.5.2

## Usage Local
```python

import asyncio
from goslideapi import GoSlideLocal

loop = asyncio.get_event_loop()
goslide = GoSlideLocal()

result = loop.run_until_complete(goslide.slide_add("192.168.1.1", "anypassword", 2))
slide = loop.run_until_complete(goslide.slide_info("192.168.1.1"))
loop.run_until_complete(goslide.slide_open("192.168.1.1"))
loop.run_until_complete(goslide.slide_close("192.168.1.1"))

```

## Usage Cloud
```python

import asyncio
from goslideapi import GoSlideCloud

loop = asyncio.get_event_loop()
goslide = GoSlideCloud('email', 'password')

login = loop.run_until_complete(goslide.login())
if login:

    # Get the slide list
    slides = loop.run_until_complete(goslide.slides_overview())
    if slides:
        for slidedev in slides:
            print(slidedev['device_id'], slidedev['device_name'])
            print('   ', slidedev['device_info']['pos'])
    else:
      print('Something went wrong while retrieving the slide information')

    # Open slide with id 1
    result = loop.run_until_complete(goslide.slide_open(1))
    if result:
        print('Succesfully opened slide 1')
    else:
        print('Failed opened slide 1')

    # Close slide with id 1
    result = loop.run_until_complete(goslide.slide_close(1))

    loop.run_until_complete(goslide.logout())
else:
    print('login failed')
```

## License

Apache License 2.0

