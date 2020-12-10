
// Write a page with a selector showing ids. (including HTML and Javascript)
// Once an option is selected, corresponding data ("title", "url", "thumbnailUrl") about the photo is displayed
// https://jsonplaceholder.typicode.com/photos/2

// Fotos von der API holen -> fetch > json
// Antwort von der API in eigene Variable speichern "var photos"
// IDs der Fotos ausgeben (in dem Select "photos" jeweils als Options ausgeben
// Wenn dort was ausgewählt wurde, das entsprechende Foto ausgeben



var photos = []

function outputSelectedPhotos() {
    console.log(photos)
    let selectTag = document.getElementById('photos')
    let optionTag

    photos.forEach(photo => {
        optionTag = document.createElement('option')
        optionTag.value = photo.id
        optionTag.innerHTML = photo.id + ' // ' + photo.title
        selectTag.appendChild(optionTag)
    })
}

function outputPhoto() {
    var selectTag = document.getElementById('photos');
    var selectedValue = selectTag.options[selectTag.selectedIndex].value;
    let photo = photos.find(p => p.id === Number(selectedValue))
    let outputPhotoTag = document.getElementById('outputPhoto')
    let imgTag = document.createElement('img')
    imgTag.src = photo.url
    let h3Tag = document.createElement('h3')
    h3Tag.innerHTML = photo.title
    outputPhotoTag.innerHTML = ''
    outputPhotoTag.appendChild(h3Tag)
    outputPhotoTag.appendChild(imgTag)
}

function fetchPhotos() {
    var url = 'https://jsonplaceholder.typicode.com/photos/'
    fetch(url).then((resp) => resp.json())
        .then(function(response){
            photos = response
            outputSelectedPhotos()
    })
}

fetchPhotos()