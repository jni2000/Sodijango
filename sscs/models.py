from django.db import models


# Create your models here.
class SoftwareSecurityScan(models.Model):
    date = models.DateTimeField(auto_now_add=True)
    type = models.CharField(max_length=32, default="binary")
    name = models.TextField(default="")
    location = models.TextField(default="")
    level = models.CharField(max_length=32, default="default")
    note = models.TextField(default="None")
    status = models.CharField(max_length=32, editable=False, default="in-progress")
    ref_id = models.CharField(max_length=256, editable=False, default="1234-abcd")
    handler = models.IntegerField(default=-1)
    product = models.TextField(default="Unknown")
    release = models.TextField(default="Unknown")
    vendor = models.TextField(default="Unknown")
    revision_reason = models.TextField(default="Unknown")

    def __str__(self):
        return self.name

class SoftwareSecuritySign(models.Model):
    date = models.DateTimeField(auto_now_add=True)
    type = models.CharField(max_length=32, default="software")
    name = models.TextField(default="")
    data = models.CharField(max_length=8192, default="")
    note = models.TextField(default="None")
    status = models.CharField(max_length=32, editable=False, default="in-progress")
    ref_id = models.CharField(max_length=256, editable=False, default="1234-sign")
    sha = models.CharField(max_length=256, editable=False)
    sha_type = models.CharField(max_length=32, editable=False, default="256")
    signature = models.CharField(max_length=256, editable=False, default="none")

    def __str__(self):
        return self.name
    

