use alloc::string::String;
use alloc::vec::Vec;

use serde::Deserialize;
use serde::Serialize;

use crate::time::i64_to_iso_time_string;
use crate::DateString;
use crate::LinkedEntityKeychainMeshId;
use crate::MeshId;
use crate::MeshLinkCode;

const MAX_PENDING_IMAGES: usize = 10;

// for messages

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ImageObjectSize {
    pub width: u16,
    pub height: u16,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ImageObject {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<MeshId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<ImageObjectSize>,
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upload_date: Option<DateString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
}

// for stored data

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ImageObjectSizeData {
    pub width: u16,
    pub height: u16,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ImageObjectData {
    pub id: MeshId,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<ImageObjectSizeData>,
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<MeshLinkCode>,
    pub upload_date: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ImageObjectListData {
    pub images: Vec<ImageObjectData>,
    pub pending_images: Vec<ImageObjectData>,
    pub filesystem_lemid: Option<LinkedEntityKeychainMeshId>,
}

impl From<ImageObjectSizeData> for ImageObjectSize {
    fn from(size_data: ImageObjectSizeData) -> ImageObjectSize {
        ImageObjectSize {
            width: size_data.width,
            height: size_data.height,
        }
    }
}

impl From<ImageObjectSize> for ImageObjectSizeData {
    fn from(size_data: ImageObjectSize) -> ImageObjectSizeData {
        ImageObjectSizeData {
            width: size_data.width,
            height: size_data.height,
        }
    }
}

impl From<ImageObjectData> for ImageObject {
    fn from(image_data: ImageObjectData) -> ImageObject {
        ImageObject {
            id: Some(image_data.id),
            name: Some(image_data.name),
            size: image_data.size.map(|size| size.into()),
            url: image_data.url,
            upload_date: Some(i64_to_iso_time_string(image_data.upload_date)),
            content_type: image_data.content_type,
        }
    }
}

impl ImageObjectListData {
    pub fn add_image(&mut self, image: ImageObjectData) {
        if self
            .images
            .iter()
            .any(|check_image| check_image.name == image.name || check_image.id == image.id)
        {
            return;
        }
        self.images.push(image);
    }

    pub fn add_pending_image(&mut self, image: ImageObjectData) {
        if let Some(index) = self
            .pending_images
            .iter()
            .position(|check_image| image.name == check_image.name)
        {
            self.pending_images.remove(index);
        }
        self.pending_images.push(image);
        if self.pending_images.len() > MAX_PENDING_IMAGES {
            self.pending_images
                .drain(0..self.pending_images.len() - MAX_PENDING_IMAGES);
        }
    }

    pub fn contains_image_name(&self, name: &str) -> bool {
        self.images.iter().any(|image| image.name == *name)
    }

    pub fn get_image(&self, id: MeshId) -> Option<&ImageObjectData> {
        self.images.iter().find(|image| image.id == id)
    }

    pub fn remove_pending_image(&mut self, token: &MeshLinkCode) -> Option<ImageObjectData> {
        if let Some(index) = self
            .pending_images
            .iter()
            .position(|image| image.token.as_ref() == Some(token))
        {
            Some(self.pending_images.remove(index))
        } else {
            None
        }
    }

    pub fn remove_image(&mut self, id: MeshId) -> bool {
        if let Some(index) = self.images.iter().position(|image| image.id == id) {
            self.images.remove(index);
            true
        } else {
            false
        }
    }

    pub fn remove_image_by_name(&mut self, name: &str) -> Option<MeshId> {
        if let Some(index) = self.images.iter().position(|image| image.name == name) {
            let id = self.images[index].id;
            self.images.remove(index);
            Some(id)
        } else {
            None
        }
    }
}
