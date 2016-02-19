from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from io import BytesIO

import PyPDF2


def new_pdf(details, name, width=216, height=280):
    """Creates a new empty PDF file"""
    pdfobj = PyPDF2.PdfFileWriter()
    pdfobj.addMetadata(details)
    pdfobj.addBlankPage(width, height)
    pdfio = BytesIO()
    pdfobj.write(pdfio)
    pdfio.seek(0)
    return {"data": pdfio,
            "name": name}


def new_email(pdfs):
    msg = MIMEMultipart()
    for pdf in pdfs.values():
        stream = pdf["data"]
        stream.seek(0)
        data = stream.read()
        pdfp = MIMEApplication(data, "pdf", name=pdf["name"])
        pdfp.add_header("Content-Disposition", "attachment",
                        filename=pdf["name"])
        msg.attach(pdfp)
    return msg


class PDFWithAttachments():
    def __init__(self, details, name, width=216, height=280):
        self._images = []
        self.pdfobj = PyPDF2.PdfFileWriter()
        self.pdfobj.addMetadata(details)
        self.page = self.pdfobj.addBlankPage(width, height)

    def addAttachment(self, name, data):
        self.pdfobj.addAttachment(name, data)

    def as_file(self):
        pdfio = BytesIO()
        self.pdfobj.write(pdfio)
        pdfio.seek(0)
        return pdfio


