
const API_BASE_URL = "http://127.0.0.1:8000";

const token = localStorage.getItem("access_token");

const userInfo = document.getElementById("userInfo");
const documentsContainer =
    document.getElementById("documentsContainer");
const message = document.getElementById("message");

if (!token) {
    window.location.href = "index.html";
}


// ===============================
// LOAD DOCUMENTS
// ===============================

async function loadDocuments(filename = "", category = "") {

    documentsContainer.textContent =
        "Loading documents...";

    try {

        const params = new URLSearchParams();

        if (filename) {
            params.append("filename", filename);
        }

        if (category) {
            params.append("category", category);
        }

        const queryString = params.toString();

        const url = queryString
            ? `${API_BASE_URL}/documents?${queryString}`
            : `${API_BASE_URL}/documents`;

        const response = await fetch(url, {
            method: "GET",
            headers: {
                "Authorization": `Bearer ${token}`
            }
        });

        const data = await response.json();

        if (!response.ok) {

            if (response.status === 401) {

                localStorage.removeItem(
                    "access_token"
                );

                window.location.href =
                    "index.html";

                return;
            }

            documentsContainer.textContent =
                data.detail ||
                "Unable to load documents.";

            return;
        }

        if (data.length === 0) {

            documentsContainer.textContent =
                "No documents found.";

            return;
        }

        documentsContainer.innerHTML = "";

        data.forEach(doc => {

            const documentCard =
                document.createElement("div");

            documentCard.className =
                "document-item";


            // =====================================
            // CREATE BUTTONS BASED ON PERMISSION
            // =====================================

            let actionButtons = "";

            // -------------------------------------
            // OWNER
            // -------------------------------------

            if (doc.permission === "OWNER") {

                actionButtons = `
                    <button
                        onclick="downloadDocument(${doc.id})"
                    >
                        Download
                    </button>

                    <button
                        onclick="editDocument(${doc.id})"
                    >
                        Edit
                    </button>

                    <button
                        onclick="deleteDocument(${doc.id})"
                    >
                        Delete
                    </button>

                    <button
                        onclick="managePermission(${doc.id})"
                    >
                        Manage Access
                    </button>

                    <button
                        onclick="revokePermission(${doc.id})"
                    >
                        Revoke Access
                    </button>
                `;
            }

            // -------------------------------------
            // EDIT PERMISSION
            // -------------------------------------

            else if (doc.permission === "EDIT") {

                actionButtons = `
                    <button
                        onclick="downloadDocument(${doc.id})"
                    >
                        Download
                    </button>

                    <button
                        onclick="editDocument(${doc.id})"
                    >
                        Edit
                    </button>
                `;
            }

            // -------------------------------------
            // READ PERMISSION
            // -------------------------------------

            else if (doc.permission === "READ") {

                actionButtons = `
                    <button
                        onclick="downloadDocument(${doc.id})"
                    >
                        Download
                    </button>
                `;
            }

            // -------------------------------------
            // UNKNOWN / NO PERMISSION
            // -------------------------------------

            else {

                actionButtons = `
                    <button
                        onclick="downloadDocument(${doc.id})"
                    >
                        Download
                    </button>
                `;
            }


            // =====================================
            // DOCUMENT CARD
            // =====================================

            documentCard.innerHTML = `
                <div>
                    <h3>
                        ${escapeHtml(doc.filename)}
                    </h3>

                    <p>
                        Category:
                        ${escapeHtml(doc.category)}
                    </p>

                    <p>
                        Permission:
                        ${escapeHtml(
                            doc.permission || "NONE"
                        )}
                    </p>
                </div>

                <div class="document-actions">
                    ${actionButtons}
                </div>
            `;

            documentsContainer.appendChild(
                documentCard
            );

        });

    } catch (error) {

        console.error(error);

        documentsContainer.textContent =
            "Unable to connect to the server.";
    }
}


// ===============================
// DOWNLOAD DOCUMENT
// ===============================

async function downloadDocument(documentId) {

    try {

        const response = await fetch(
            `${API_BASE_URL}/documents/${documentId}/download`,
            {
                method: "GET",

                headers: {
                    "Authorization": `Bearer ${token}`
                }
            }
        );

        if (!response.ok) {

            const data =
                await response.json();

            message.textContent =
                data.detail ||
                "Download failed.";

            return;
        }

        const blob =
            await response.blob();

        const contentDisposition =
            response.headers.get(
                "Content-Disposition"
            );

        let filename =
            "downloaded_document";

        if (contentDisposition) {

            const match =
                contentDisposition.match(
                    /filename="?([^"]+)"?/
                );

            if (match) {
                filename = match[1];
            }
        }

        const url =
            window.URL.createObjectURL(
                blob
            );

        const link =
            document.createElement("a");

        link.href = url;

        link.download =
            filename;

        document.body.appendChild(
            link
        );

        link.click();

        link.remove();

        window.URL.revokeObjectURL(
            url
        );

        message.textContent =
            "Download successful.";

    } catch (error) {

        console.error(error);

        message.textContent =
            "Unable to connect to the server.";
    }
}


// ===============================
// ESCAPE HTML
// ===============================

function escapeHtml(value) {

    const div =
        document.createElement("div");

    div.textContent =
        value;

    return div.innerHTML;
}


// ===============================
// EDIT DOCUMENT
// ===============================

async function editDocument(documentId) {

    const fileInput =
        document.createElement("input");

    fileInput.type =
        "file";

    fileInput.accept =
        ".pdf,.txt,.jpg,.jpeg,.png";

    fileInput.addEventListener(
        "change",
        async function () {

            const file =
                fileInput.files[0];

            if (!file) {
                return;
            }

            const formData =
                new FormData();

            formData.append(
                "file",
                file
            );

            message.textContent =
                "Updating document...";

            try {

                const response =
                    await fetch(
                        `${API_BASE_URL}/documents/${documentId}`,
                        {
                            method: "PUT",

                            headers: {
                                "Authorization":
                                    `Bearer ${token}`
                            },

                            body: formData
                        }
                    );

                const data =
                    await response.json();

                if (!response.ok) {

                    message.textContent =
                        data.detail ||
                        "Update failed.";

                    return;
                }

                message.textContent =
                    "Document updated successfully.";

                await loadDocuments();

            } catch (error) {

                console.error(error);

                message.textContent =
                    "Unable to connect to the server.";
            }
        }
    );

    fileInput.click();
}


// ===============================
// DELETE DOCUMENT
// ===============================

async function deleteDocument(documentId) {

    const confirmed =
        confirm(
            "Are you sure you want to delete this document?"
        );

    if (!confirmed) {
        return;
    }

    try {

        const response =
            await fetch(
                `${API_BASE_URL}/documents/${documentId}`,
                {
                    method: "DELETE",

                    headers: {
                        "Authorization":
                            `Bearer ${token}`
                    }
                }
            );

        const data =
            await response.json();

        if (!response.ok) {

            message.textContent =
                data.detail ||
                "Delete failed.";

            return;
        }

        message.textContent =
            "Document deleted successfully.";

        await loadDocuments();

    } catch (error) {

        console.error(error);

        message.textContent =
            "Unable to connect to the server.";
    }
}


// ===============================
// MANAGE DOCUMENT PERMISSION
// ===============================

async function managePermission(documentId) {

    const userId =
        prompt(
            "Enter the user ID to give access:"
        );

    if (!userId) {
        return;
    }

    const permission =
        prompt(
            "Enter permission: READ or EDIT"
        );

    if (!permission) {
        return;
    }

    const selectedPermission =
        permission
            .trim()
            .toUpperCase();

    if (
        selectedPermission !== "READ" &&
        selectedPermission !== "EDIT"
    ) {

        message.textContent =
            "Permission must be READ or EDIT.";

        return;
    }

    try {

        const response =
            await fetch(
                `${API_BASE_URL}/documents/${documentId}/permissions`,
                {
                    method: "POST",

                    headers: {
                        "Authorization":
                            `Bearer ${token}`,

                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify({
                        user_id:
                            Number(userId),

                        permission:
                            selectedPermission
                    })
                }
            );

        const data =
            await response.json();

        if (!response.ok) {

            message.textContent =
                data.detail ||
                "Permission update failed.";

            return;
        }

        message.textContent =
            `${selectedPermission} permission granted successfully.`;

        // Refresh document list
        await loadDocuments();

    } catch (error) {

        console.error(error);

        message.textContent =
            "Unable to connect to the server.";
    }
}


// ===============================
// REVOKE DOCUMENT PERMISSION
// ===============================

async function revokePermission(documentId) {

    const userId =
        prompt(
            "Enter the user ID whose access should be revoked:"
        );

    if (!userId) {
        return;
    }

    const confirmed =
        confirm(
            `Are you sure you want to revoke access for user ${userId}?`
        );

    if (!confirmed) {
        return;
    }

    try {

        const response =
            await fetch(
                `${API_BASE_URL}/documents/${documentId}/permissions/revoke`,
                {
                    method: "POST",

                    headers: {
                        "Authorization":
                            `Bearer ${token}`,

                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify({
                        user_id:
                            Number(userId)
                    })
                }
            );

        const data =
            await response.json();

        if (!response.ok) {

            message.textContent =
                data.detail ||
                "Permission revoke failed.";

            return;
        }

        message.textContent =
            "Permission revoked successfully.";

        // Refresh document list
        await loadDocuments();

    } catch (error) {

        console.error(error);

        message.textContent =
            "Unable to connect to the server.";
    }
}


// ===============================
// SEARCH BUTTON
// ===============================

document
    .getElementById("searchButton")
    .addEventListener(
        "click",
        function () {

            const filename =
                document
                    .getElementById(
                        "searchFilename"
                    )
                    .value
                    .trim();

            const category =
                document
                    .getElementById(
                        "searchCategory"
                    )
                    .value;

            loadDocuments(
                filename,
                category
            );
        }
    );


// ===============================
// REFRESH BUTTON
// ===============================

document
    .getElementById("refreshButton")
    .addEventListener(
        "click",
        function () {

            loadDocuments();

        }
    );


// ===============================
// LOGOUT BUTTON
// ===============================

document
    .getElementById("logoutButton")
    .addEventListener(
        "click",
        function () {

            localStorage.removeItem(
                "access_token"
            );

            window.location.href =
                "index.html";
        }
    );


// ===============================
// USER INFO
// ===============================

userInfo.textContent =
    "Authenticated user";


// ===============================
// INITIAL DOCUMENT LOAD
// ===============================

loadDocuments();


// ===============================
// UPLOAD DOCUMENT
// ===============================

const uploadForm =
    document.getElementById(
        "uploadForm"
    );

const uploadMessage =
    document.getElementById(
        "uploadMessage"
    );

uploadForm.addEventListener(
    "submit",
    async function (event) {

        event.preventDefault();

        const fileInput =
            document.getElementById(
                "file"
            );

        const category =
            document.getElementById(
                "category"
            );

        const file =
            fileInput.files[0];

        if (!file) {

            uploadMessage.textContent =
                "Please select a file.";

            return;
        }

        const formData =
            new FormData();

        formData.append(
            "file",
            file
        );

        formData.append(
            "category",
            category.value
        );

        uploadMessage.textContent =
            "Uploading...";

        try {

            const response =
                await fetch(
                    `${API_BASE_URL}/documents/upload?category=${encodeURIComponent(category.value)}`,
                    {
                        method: "POST",

                        headers: {
                            "Authorization":
                                `Bearer ${token}`
                        },

                        body: formData
                    }
                );

            const data =
                await response.json();

            if (!response.ok) {

                uploadMessage.textContent =
                    data.detail ||
                    "Upload failed.";

                return;
            }

            uploadMessage.textContent =
                "Document uploaded successfully.";

            uploadForm.reset();

            await loadDocuments();

        } catch (error) {

            console.error(error);

            uploadMessage.textContent =
                "Unable to connect to the server.";
        }
    }
);
