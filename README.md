
# GoSlide Open Cloud API

Python API to utilise the GoSlide Open Cloud JSON API

## Requirements

- Python >= 3.5.2

## Usage
```python

import asyncio
from goslideapi import GoSlideCloud

loop = asyncio.get_event_loop()
goslide = GoSlideCloud('email', 'password')

login = loop.run_until_complete(goslide.login())
if login:

    # Get the slide list
    slides = loop.run_until_complete(goslide.slidesoverview())
    if slides:
        for slidedev in slides:
            print(slidedev['device_id'], slidedev['device_name'])
            print('   ', slidedev['device_info']['pos'])
    else:
      print('Something went wrong while retrieving the slide information')

    # Open slide with id 1
    result = loop.run_until_complete(goslide.slideopen(1))  
    if result:
        print('Succesfully opened slide 1')
    else:
        print('Failed opened slide 1')

    # Close slide with id 1
    result = loop.run_until_complete(goslide.slideclose(1))

    loop.run_until_complete(goslide.logout())
else:
    print('login failed')
```

## TODO:

- Test with a real slide (awaiting delivery ;-))
- Expose more API functions

## License

Apache License 2.0

