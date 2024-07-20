# Gouge: Gouge for URLs!

## What is Gouge?

Gouge is a simple Burp extension to extract or gouge all URLs which are seen in JS files as you visit different websites/webpages in Burp Suite. It is a Burp Suite extension written in Python and uses the Burp Suite API to extract URLs from JS files.

## How to use Gouge?

1. Download the latest release of Gouge from the [releases page](https://github.com/mqst/gouge).
2. Extract the Gouge zip file to a directory of your choice.
3. Open Burp Suite and go to the Extender tab.
4. Click on the "Add" button and select the Gouge.py file from the extracted Gouge directory.
5. Go to the Gouge tab and click on the "Gouge" button to start Gouging.

## How to build Gouge?

Gouge is written in Python and uses the Burp Suite API to extract URLs from JS files. To build Gouge, you need to have Python installed on your computer. You can download Python from the [official Python website](https://www.python.org/downloads/).

Once you have Python installed, you can build Gouge by following these steps:

1. Open a terminal or command prompt and navigate to the directory where you have extracted the Gouge source code.
2. Run the following command to install the required dependencies:

```
pip install -r requirements.txt
```
## How to contribute to Gouge?

If you have any suggestions or improvements for Gouge, please open an issue or submit a pull request on the [Gouge GitHub repository](https://github.com/mqst/gouge).
