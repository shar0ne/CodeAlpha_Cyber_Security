
const quizData = [
    {
        question: "If a sender address claims to be a brand but ends with '@gmail.com' and contains spelling mistakes, what does it mean?",
        options: [
            "It is completely standard for remote customer support teams.",
            "It is a highly critical indicator of a phishing attempt.",
            "The message communication channel is fully verified by Google."
        ],
        answer: 1
    },
    {
        question: "What is the correct security posture when an email demands an immediate upfront fee to release a large cash transfer?",
        options: [
            "Pay the fee quickly to prevent the transaction from expiring.",
            "Contact your local provider immediately to process the deposit.",
            "Delete the email. It is an advance-fee scam designed for financial extortion."
        ],
        answer: 2
    }
];

let currentQuestionIndex = 0;

const questionElement = document.getElementById("question-text");
const optionsContainer = document.getElementById("options-container");
const nextButton = document.getElementById("next-btn");

function loadQuestion() {
    const currentQuestion = quizData[currentQuestionIndex];
    questionElement.textContent = currentQuestion.question;
    optionsContainer.innerHTML = "";
    nextButton.style.display = "none";

    currentQuestion.options.forEach((option, index) => {
        const li = document.createElement("li");
        li.className = "option-item";
        li.textContent = option;
        li.addEventListener("click", () => selectOption(index, li));
        optionsContainer.appendChild(li);
    });
}

function selectOption(selectedIndex, element) {
    const correctAnswer = quizData[currentQuestionIndex].answer;
    const allOptions = document.querySelectorAll(".option-item");
    
    allOptions.forEach(opt => opt.style.pointerEvents = "none");

    if (selectedIndex === correctAnswer) {
        element.style.borderColor = "#4169e1";
        element.style.background = "rgba(65, 105, 225, 0.15)";
        element.style.color = "#ffffff";
    } else {
        element.style.borderColor = "#3a3a4f";
        element.style.background = "rgba(255, 255, 255, 0.02)";
        
        // Met en valeur la bonne réponse de manière sobre
        allOptions[correctAnswer].style.borderColor = "#4169e1";
        allOptions[correctAnswer].style.color = "#ffffff";
    }
    
    nextButton.style.display = "inline-block";
}

nextButton.addEventListener("click", () => {
    currentQuestionIndex++;
    if (currentQuestionIndex < quizData.length) {
        loadQuestion();
    } else {
        document.getElementById("quiz-box").innerHTML = `
            <h3 style='color: #4169e1; text-align: center; font-size: 26px; margin-bottom: 15px;'>Evaluation Complete!</h3>
            <p style='text-align: center; color: #a9a9b3;'>You have successfully processed all phishing analysis modules.</p>
        `;
    }
});

document.addEventListener("DOMContentLoaded", loadQuestion);