import React from 'react'
import { shallow } from 'enzyme'

import ActionsWidget from './ActionsWidget';
import Question from "metabase-lib/lib/Question";
import {
    DATABASE_ID,
    ORDERS_TABLE_ID,
    ORDERS_PRODUCT_FK_FIELD_ID,
    metadata
} from "metabase/__support__/sample_dataset_fixture";

const getActionsWidget = (question) =>
    <ActionsWidget
        question={question}
        card={question.card()}
        setCardAndRun={() => {}}
        navigateToNewCardInsideQB={() => {}}
    />

describe('ActionsWidget', () => {
    it("should be shown if you have a breakout but no aggregation in your question", () => {
        const question: Question = Question.create({databaseId: DATABASE_ID, tableId: ORDERS_TABLE_ID, metadata})
            .query()
            .addBreakout(["field-id"], ORDERS_PRODUCT_FK_FIELD_ID)
            .question();

        const component = shallow(getActionsWidget(question));

        console.log(component.debug())
        expect(component.children().children().length).toBeGreaterThan(0);
    });
});