<div id="top"></div>


<br />
<h3 align="center">DuoCapiti</h3>

  <p align="center">
    DuoCapiti Malware implementation fragment
    <br />
        <a href="https://github.com/Hato0/DuoCapiti"><strong>Explore the docs »</strong></a>
    <br />
    <br />
    <a href="https://github.com/Hato0/DuoCapiti/issues">Report Bug</a>
    ·
    <a href="https://github.com/Hato0/DuoCapiti/issues">Request Feature</a>
  </p>
</div>

## About The Project

This is a partial implementation of the DuoCapiti malware capabilities. This project is here to give an example of malware implementation and in particular the basic capabilities of DuoCapiti. 


## Getting Started

You can clone or fork this repository to start using it. 

### Prerequisites

You will need a CPP compiler.

The faster way is to install Visual Studio and follow their [documentation](https://learn.microsoft.com/en-us/visualstudio/ide/compiling-and-building-in-visual-studio?view=vs-2022) to compile cpp code.

### Installation

Clone this github repository and start using it !
```bash
git clone https://github.com/Hato0/DuoCapiti.git
```

## Usage

I will not guide you to use it fully, you will have to understand the code. 
I can still give you the basics: 
- Step1:
  - Change powershell encoded command to fit your infra
  - Adapt the OS version limitation 
  - Adapt keyboard whitelisting
- Step2:
  - Change shellcode to fit your need
  - Declare Discord API token
  - Declare Discord channel ID
  - Adapt information you want to exfil 

## Demo version capabilities

- Stage1:
  - [X] Retrieve basic OS info
  - [X] Check for execution in sandbox
  - [X] Whitelist states based on keyboards setup
  - [X] Cleanup some security solution
  - [X] UAC Bypass
  - [X] Stage2 download and execution
- Stage2:
  - [X] Create in memory zip
  - [X] Exfiltrate data
  - [X] Decode shellcode and execute it
  - [X] Persistance over schedule task (basic, not the actual way)

See the [open issues](https://github.com/Hato0/DuoCapiti) for a full list of proposed features (and known issues).

## License

Distributed under the MIT License. See `LICENSE` for more information.

## Contact

hato0 - hato0@protonmail.ch

Project Link: [https://github.com/Hato0/DuoCapiti](https://github.com/Hato0/DuoCapiti)

<p align="right">(<a href="#top">back to top</a>)</p>