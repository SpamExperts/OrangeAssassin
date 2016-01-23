from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from io import BytesIO
from PIL import Image


def new_image(width, height, subtype, name):
    image = Image.new("RGB", (width, height))
    img_io = BytesIO()
    image.save(img_io, format="JPEG")
    img_io.seek(0)
    return {"data": img_io,
            "name": name,
            "subtype": subtype,
            "width": width,
            "height": height,
            "coverage": width*height}


def new_email(images):
    msg = MIMEMultipart()
    for image in images.values():
        mimg = MIMEImage(image['data'].read(), _subtype=image['subtype'],
                         name=image['name'])
        mimg.add_header("Content-Disposition", "attachment",
                        filename=image["name"])
        msg.attach(mimg)
    return msg


def new_image_string(size, mode="RGB"):
    image = Image.new(mode, size)
    img_io = BytesIO()
    image.save(img_io, format="JPEG")
    image.close()
    img_io.seek(0)
    return img_io.read()
