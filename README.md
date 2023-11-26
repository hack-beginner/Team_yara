# Team_yara
creating a yara rule generator

Example
Usage is as follows with an example of a basic search + hitting all of the switches below:

```
usage: yaraGenerator.py [-h] -r RULENAME -f FILETYPE [-a AUTHOR] [-d DESCRIPTION] [-t TAGS] InputDirectory 

YaraGenerator

positional arguments:
  InputDirectory        Path To Files To Create Yara Rule From

optional arguments:
  -h , --help             show this help message and exit
  -r , --RuleName         Enter A Rule/Alert Name (No Spaces + Must Start with Letter)
  -a , --Author           Enter Author Name
  -d , --Description      Provide a useful description of the Yara Rule
  -t , --Tags             Apply Tags to Yara Rule For Easy Reference (AlphaNumeric)
  -v , --Verbose          Print Finished Rule To Standard Out
  -f , --FileType         Select Sample Set FileType choices are: unknown, exe,
                          pdf, email, office, js-html
```

Thanks
